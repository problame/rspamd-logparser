use std::collections::HashMap;
fn main() {
    use env_logger;
    env_logger::init();

    let fp = std::env::args()
        .nth(1)
        .expect("first argument must be a file path");
    let input = std::fs::read_to_string(fp).expect("cannot read input file");
    let mut spans: HashMap<String, RspamdSpan> = HashMap::new(); // by span id
    for line in input.lines() {
        log::info!("line: {:?}", line);
        if let Ok(msgparse_line) = parse_message_parse_line(line) {
            let span = spans.entry(msgparse_line.log_span.clone()).or_default();
            span.msg_parse = Some(msgparse_line);
        } else if let Ok(result_line) = parse_result_line(line) {
            let span = spans.entry(result_line.log_span.clone()).or_default();
            span.result = Some(result_line);
        }
    }
    run_repl(&spans).unwrap();
}

fn run_repl(spans: &HashMap<String, RspamdSpan>) -> Result<(), Error> {
    use linefeed::{Interface, ReadResult};
    let reader = Interface::new("rspamd-logparser")?;
    reader.set_history_size(1000);

    reader.set_prompt("rspamd-logparser> ")?;

    let mut search_idx: HashMap<&String, (&RspamdSpan, String)> = HashMap::new();
    for (span, rspamd_span) in spans.iter() {
        let mut printout = Vec::new();
        write_repl_search_result(&mut printout, span, rspamd_span);
        let printout = String::from_utf8(printout).unwrap();
        search_idx.insert(span, (rspamd_span, printout));
    }

    while let ReadResult::Input(input) = reader.read_line()? {
        if input.is_empty() {
            continue;
        }

        reader.add_history_unique(input.clone());

        let pattern = match regex::Regex::new(&input) {
            Ok(re) => re,
            Err(e) => {
                println!("invalid regex: {}", e);
                continue;
            }
        };

        let matches = search_idx
            .iter()
            .filter(|(_, (e, output))| {
                let result_metadata = e.result.as_ref().map(|r| &r.metadata_items);
                let parse_metadata = e.msg_parse.as_ref().map(|r| &r.metadata_items);
                let mut combined = result_metadata
                    .iter()
                    .chain(parse_metadata.iter())
                    .map(|vec| vec.iter())
                    .flatten();
                if combined.any(|(_, v)| pattern.is_match(v)) {
                    return true;
                }
                pattern.is_match(output)
            })
            .collect::<Vec<_>>();

        for (_, (_, output)) in matches {
            println!("{}\n", output);
        }
    }

    Ok(())
}

fn write_repl_search_result(out: &mut std::io::Write, id: &str, span: &RspamdSpan) {
    writeln!(out, "log span: {}", id);
    macro_rules! print_metadata {
        ($items:expr) => {
            for (k, v) in $items {
                writeln!(out, "  {}: {}", k, v);
            }
        };
    }
    writeln!(out, "Combined Metadata:");
    if let Some(parse) = &span.msg_parse {
        print_metadata!(&parse.metadata_items);
    }
    if let Some(result) = &span.result {
        print_metadata!(&result.metadata_items);
    }

    if let Some(result) = &span.result {
        writeln!(out, "Symbols:");
        for sym in &result.syms {
            writeln!(out, "  {: >5.2}\t{}\t{}", sym.score, sym.name, sym.info);
        }
    }
}

#[derive(Debug, Default)]
pub struct RspamdSpan {
    pub msg_parse: Option<MessageParseLine>,
    pub result: Option<RspamdResult>,
}

#[derive(Debug, PartialEq)]
pub struct SymbolEntry {
    pub name: String,
    pub score: f64,
    pub info: String,
}

#[derive(Debug)]
pub struct MessageParseLine {
    pub log_span: String,
    pub metadata_items: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct RspamdResult {
    pub log_span: String,
    pub metadata_items: Vec<(String, String)>,
    pub syms: Vec<SymbolEntry>,
}

use failure::{format_err, Error, ResultExt};

use lazy_static::lazy_static;

use std::str::FromStr;

macro_rules! re {
    ($varname:ident, $re:expr) => {
        lazy_static! {
            static ref $varname: regex::Regex = regex::Regex::new($re).unwrap();
        }
    };
}

pub fn parse_message_parse_line(line: &str) -> Result<MessageParseLine, Error> {
    re!(linestructure, r".*<(?P<rspamd_log_span>.*)>; task; rspamd_message_parse: loaded message; (?P<metadata>.*)");
    let captures = linestructure
        .captures(line)
        .ok_or_else(|| format_err!("line does not match pattern"))?;

    let metadata_items = &captures["metadata"];
    let metadata_items = parse_paren_delim_list(metadata_items, ';');

    let metadata_items = metadata_items
        .into_iter()
        .map(|s| {
            let mut kv = s.splitn(2, ':').map(|x| x.trim().to_owned());
            log::debug!("{:?}", s);
            (kv.next().unwrap(), kv.next().unwrap())
        })
        .collect();

    Ok(MessageParseLine {
        log_span: captures["rspamd_log_span"].to_owned(),
        metadata_items,
    })
}

pub fn parse_result_line(line: &str) -> Result<RspamdResult, Error> {
    re!(
        linestructure,
        r".*<(?P<rspamd_log_span>.*)>; task; rspamd_task_write_log: (?P<metadata>.*)"
    );
    let captures = linestructure
        .captures(line)
        .ok_or_else(|| format_err!("line does not match pattern"))?;
    let metadata = &captures["metadata"];
    log::debug!("metadata: {:?}", metadata);

    let metatadata_items = parse_paren_delim_list(metadata, ',');
    log::debug!("metatadat_items: {:#?}", metatadata_items);

    // find the metadata item that contains the spam symbols
    let (spam_symbol_metadata_item_idx, item) = metatadata_items
        .iter()
        .enumerate()
        .find(|(_, el)| el.starts_with('('))
        .ok_or_else(|| format_err!("cannot find spam sybmol metadata item"))?;
    log::debug!("spam sym entry: {:#?}", item);

    re!(
        item_structure,
        r"\(\w+: [^:].*: \[(?P<score>[\d\.].*)/(?P<total>[\d\.].*)\] \[(?P<symlist>.*)\]"
    );
    let item_captures = item_structure
        .captures(item)
        .ok_or_else(|| format_err!("unexcpeted spam sym entry format: {:?}", item))?;

    log::debug!(
        "item_captures: {:#?}",
        item_captures.iter().collect::<Vec<_>>()
    );

    let syms = parse_paren_delim_list(&item_captures["symlist"], ',');
    log::debug!("syms: {:?}", syms);

    re!(sym_regex, r"(?P<name>.*)\((?P<score>.*)\)\{(?P<info>.*)\}$");
    let syms = syms
        .into_iter()
        .map(|s| (s, sym_regex.captures(s)))
        .map(|(s, c)| {
            let c = c.ok_or_else(|| format_err!("sym_regex does not match: {:?}", s))?;
            let score = f64::from_str(&c["score"]).context(format_err!("cannot parse score"))?;
            Ok(SymbolEntry {
                name: c["name"].to_owned(),
                info: c["info"].to_owned(),
                score,
            })
        })
        .collect::<Result<Vec<SymbolEntry>, Error>>()?;

    // Post-process other metadata items

    // rspamd has a bug where the values following the time: metadata field are not enclosed in
    // parentheses, hence we need to join those two metadata elements
    let metatadata_items =
        metatadata_items
            .into_iter()
            .fold(Vec::new(), |mut a: Vec<String>, i| {
                let is_unfinished = a.last().map(|top| {
                    (top.starts_with("time: ") && !top.contains("virtual"))
                        || (top.starts_with("mime_rcpts: ") && !i.contains(':'))
                        || (top.starts_with("rcpts: ") && !i.contains(':'))
                });
                if let Some(true) = is_unfinished {
                    let mut top = a.pop().unwrap().to_owned();
                    top.push_str(", ");
                    top.push_str(i);
                    a.push(top);
                } else {
                    a.push(i.to_owned());
                }
                a
            });

    let metadata_items = metatadata_items
        .into_iter()
        .enumerate()
        .filter_map(|(i, s)| {
            if i == spam_symbol_metadata_item_idx {
                None
            } else {
                Some(s)
            }
        })
        .map(|s| {
            let mut kv = s.splitn(2, ':').map(|x| x.trim().to_owned());
            log::debug!("{:?}", s);
            (kv.next().unwrap(), kv.next().unwrap())
        })
        .collect();

    let log_span = captures["rspamd_log_span"].to_owned();
    Ok(RspamdResult {
        log_span,
        syms,
        metadata_items,
    })
}

fn parse_paren_delim_list(pcl: &str, delim: char) -> Vec<&str> {
    let mut elems = Vec::new();
    let mut paren_stack = Vec::new();
    let mut current_elem_begin = 0;
    let mut push_current_elem = |pos| {
        elems.push(&pcl[current_elem_begin..pos]);
        current_elem_begin = pos;
    };
    for (pos, c) in pcl.char_indices() {
        if c == delim && paren_stack.is_empty() {
            push_current_elem(pos);
            continue;
        }
        if c == '[' || c == '(' || c == '{' {
            paren_stack.push(c);
            continue;
        }

        if let Some(top) = paren_stack.last() {
            match (top, c) {
                ('(', ')') | ('[', ']') | ('{', '}') => {
                    paren_stack.pop();
                }
                _ => (),
            }
        }
    }
    push_current_elem(pcl.len());

    elems = elems
        .into_iter()
        .map(|e| e.trim_start_matches(delim).trim())
        .collect();
    elems
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn message_parse_line() {
        let input = r"
2018-12-09T02:26:35.540412+00:00 mail rspamd[85612]: <d6d566>; task; rspamd_message_parse: loaded message; id: <E1gVong-0005T7-4m@example.com>; queue-id: <81CB53AB40>; size: 3526; checksum: <d06617f8f40ea2d48bf43d2002de2887>
        ";

        let res = parse_message_parse_line(input).unwrap();

        let (_, time_item) = res
            .metadata_items
            .iter()
            .find(|(k, _)| k.contains("queue-id"))
            .expect("cannot find queue-id metadata item");
        assert_eq!(time_item, "<81CB53AB40>");
    }

    #[test]
    fn result() {
        let input = r"
        2018-12-09 04:05:52 #24322(normal) <adafb9>; task; rspamd_task_write_log: id: <1a13fdabc13f271f6e47622c1d2887b8@hotmail.com>, qid: <6A1E5DF3A7>, ip: 183.143.43.80, from: <13065463222@hotmail.com>, (default: F (add header): [8.40/10.00] [CUSTOM_SPAMMY_COUNTRY(4.00){CN;},HFILTER_HOSTNAME_UNKNOWN(2.50){},RDNS_NONE(1.00){},SUBJECT_ENDS_SPACES(0.50){},MIME_HTML_ONLY(0.20){},DMARC_POLICY_SOFTFAIL(0.10){hotmail.com : No valid SPF, No valid DKIM;none;},RCVD_NO_TLS_LAST(0.10){},ARC_NA(0.00){},ASN(0.00){asn:4134, ipnet:183.128.0.0/11, country:CN;},FREEMAIL_ENVFROM(0.00){hotmail.com;},FREEMAIL_FROM(0.00){hotmail.com;},FROM_EQ_ENVFROM(0.00){},FROM_HAS_DN(0.00){},MID_RHS_MATCH_FROM(0.00){},RCPT_COUNT_ONE(0.00){1;},RCVD_COUNT_TWO(0.00){2;},R_DKIM_NA(0.00){},R_SPF_SOFTFAIL(0.00){~all;},TO_DN_NONE(0.00){},TO_MATCH_ENVRCPT_ALL(0.00){}]), len: 3056, time: 2298.164ms real, 9.430ms virtual, dns req: 24, digest: <0841043571534cb4a82ccfc686a3ee4d>, rcpts: <foo@example.com>, mime_rcpts: <foo@examemple.com>

        ";

        let res = parse_result_line(input).unwrap();

        macro_rules! assert_symbol_entry {
            ($entry:expr) => {
                let exp = $entry;
                let sample_sym = res
                    .syms
                    .iter()
                    .find(|s| s.name == exp.name)
                    .expect("cannot find sample symbol");

                assert_eq!(&exp, sample_sym);
            };
        }

        assert_symbol_entry!(SymbolEntry {
            name: "DMARC_POLICY_SOFTFAIL".to_string(),
            info: "hotmail.com : No valid SPF, No valid DKIM;none;".to_string(),
            score: 0.10,
        });

        let (_, time_item) = res
            .metadata_items
            .iter()
            .find(|(k, _)| k.contains("time"))
            .expect("cannot find time metadata item");
        assert_eq!(time_item, "2298.164ms real, 9.430ms virtual");
    }

    #[test]
    fn commalist() {
        let input = r"foo, bar, (bar,,,baz), (bar (baz),(baz))";
        let res = parse_paren_delim_list(input, ',');
        let exp = vec!["foo", "bar", "(bar,,,baz)", "(bar (baz),(baz))"];
        assert_eq!(res, exp);
    }

}
