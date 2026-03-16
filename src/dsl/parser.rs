// src/dsl/parser.rs
use pest::Parser;
use pest::iterators::Pair;
use pest_derive::Parser;
use crate::error::PolicyError;
use crate::dsl::ast::*;

#[derive(Parser)]
#[grammar = "dsl/grammar.pest"]
struct DslParser;

/// Parse a DSL source string into a `PolicyFile` AST.
pub fn parse(source: &str) -> Result<PolicyFile, PolicyError> {
    let pairs = DslParser::parse(Rule::policy_file, source)
        .map_err(|e| PolicyError::Parse(e.to_string()))?;
    let file_pair = pairs.into_iter().next().unwrap();
    let mut declarations = Vec::new();
    for pair in file_pair.into_inner() {
        match pair.as_rule() {
            Rule::declaration => {
                let inner = pair.into_inner().next().unwrap();
                declarations.push(parse_declaration(inner)?);
            }
            Rule::EOI => {}
            _ => {}
        }
    }
    Ok(PolicyFile { declarations })
}

fn parse_declaration(pair: Pair<Rule>) -> Result<Declaration, PolicyError> {
    match pair.as_rule() {
        Rule::grant_decl      => Ok(Declaration::Grant(parse_grant(pair)?)),
        Rule::categorize_decl => Ok(Declaration::Categorize(parse_categorize(pair)?)),
        Rule::classify_decl   => Ok(Declaration::Classify(parse_classify(pair)?)),
        Rule::pattern_decl    => Ok(Declaration::Pattern(parse_pattern(pair)?)),
        Rule::rule_decl       => Ok(Declaration::Rule(parse_rule_decl(pair)?)),
        Rule::policy_decl     => Ok(Declaration::Policy(parse_policy_decl(pair)?)),
        r => Err(PolicyError::Parse(format!("unexpected rule: {:?}", r))),
    }
}

fn parse_grant(pair: Pair<Rule>) -> Result<GrantDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let role = unquote(inner.next().unwrap().as_str());
    let perm_pair = inner.next().unwrap().into_inner().next().unwrap();
    let permission = match perm_pair.as_rule() {
        Rule::call_any      => GrantPermission::CallAny,
        Rule::call_category => {
            let s = unquote(perm_pair.into_inner().next().unwrap().as_str());
            GrantPermission::CallCategory(s)
        }
        Rule::access_pattern => {
            let s = unquote(perm_pair.into_inner().next().unwrap().as_str());
            GrantPermission::AccessPattern(s)
        }
        r => return Err(PolicyError::Parse(format!("unexpected grant perm: {:?}", r))),
    };
    Ok(GrantDecl { role, permission })
}

fn parse_categorize(pair: Pair<Rule>) -> Result<CategorizeDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let tool     = unquote(inner.next().unwrap().as_str());
    let category = unquote(inner.next().unwrap().as_str());
    Ok(CategorizeDecl { tool, category })
}

fn parse_classify(pair: Pair<Rule>) -> Result<ClassifyDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let resource_pattern = unquote(inner.next().unwrap().as_str());
    let sensitivity      = unquote(inner.next().unwrap().as_str());
    Ok(ClassifyDecl { resource_pattern, sensitivity })
}

fn parse_pattern(pair: Pair<Rule>) -> Result<PatternDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let name_tok = inner.next().unwrap().as_str();
    let name     = name_tok.trim_start_matches(':').to_string();
    let raw      = inner.next().unwrap().as_str();
    let source   = raw
        .trim_start_matches("r\"")
        .trim_end_matches('"')
        .to_string();
    Ok(PatternDecl { name, source })
}

fn parse_rule_decl(pair: Pair<Rule>) -> Result<RuleDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let name   = inner.next().unwrap().as_str().to_string();
    let params = parse_param_list(inner.next().unwrap())?;
    let conditions = parse_condition_list(inner.next().unwrap())?;
    Ok(RuleDecl { name, params, conditions })
}

fn parse_param_list(pair: Pair<Rule>) -> Result<Vec<Param>, PolicyError> {
    pair.into_inner().map(|param_pair| {
        let inner = param_pair.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::wildcard => {
                let s = inner.as_str();
                if s == "_" {
                    Ok(Param::Wildcard)
                } else {
                    Ok(Param::NamedWildcard(s[1..].to_string()))
                }
            }
            Rule::ident => Ok(Param::Named(inner.as_str().to_string())),
            r => Err(PolicyError::Parse(format!("unexpected param rule: {:?}", r))),
        }
    }).collect()
}

fn parse_condition_list(pair: Pair<Rule>) -> Result<Vec<ConditionClause>, PolicyError> {
    pair.into_inner().map(parse_condition).collect()
}

fn parse_condition(pair: Pair<Rule>) -> Result<ConditionClause, PolicyError> {
    match pair.as_rule() {
        Rule::atom_condition => Ok(ConditionClause::Atom(parse_atom(pair)?)),
        Rule::not_condition  => {
            let inner = pair.into_inner().next().unwrap();
            Ok(ConditionClause::Not(parse_atom(inner)?))
        }
        Rule::or_condition   => {
            let atoms: Result<Vec<_>, _> = pair.into_inner().map(parse_atom).collect();
            Ok(ConditionClause::Or(atoms?))
        }
        Rule::true_kw        => Ok(ConditionClause::True),
        r => Err(PolicyError::Parse(format!("unexpected condition: {:?}", r))),
    }
}

fn parse_atom(pair: Pair<Rule>) -> Result<AtomCondition, PolicyError> {
    let mut inner = pair.into_inner();
    let predicate = inner.next().unwrap().as_str().to_string();
    let args = match inner.next() {
        Some(arg_list) => arg_list.into_inner().map(parse_arg).collect::<Result<_, _>>()?,
        None           => vec![],
    };
    Ok(AtomCondition { predicate, args })
}

fn parse_arg(pair: Pair<Rule>) -> Result<Arg, PolicyError> {
    // The `arg` rule wraps the actual token; drill into the inner pair.
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::string      => Ok(Arg::StringLit(unquote(inner.as_str()))),
        Rule::integer     => Ok(Arg::Integer(inner.as_str().parse().unwrap())),
        Rule::pattern_ref => Ok(Arg::PatternRef(inner.as_str().trim_start_matches(':').to_string())),
        Rule::wildcard    => {
            let s = inner.as_str();
            if s == "_" {
                Ok(Arg::Wildcard)
            } else {
                Ok(Arg::NamedWildcard(s[1..].to_string()))
            }
        }
        Rule::ident       => Ok(Arg::Variable(inner.as_str().to_string())),
        r => Err(PolicyError::Parse(format!("unexpected arg: {:?}", r))),
    }
}

fn parse_policy_decl(pair: Pair<Rule>) -> Result<PolicyDecl, PolicyError> {
    let mut inner = pair.into_inner();
    let name     = unquote(inner.next().unwrap().as_str());
    let priority = inner.next().unwrap().as_str().parse::<u32>().unwrap();
    let rules: Result<Vec<_>, _> = inner.map(parse_policy_rule).collect();
    Ok(PolicyDecl { name, priority, rules: rules? })
}

fn parse_policy_rule(pair: Pair<Rule>) -> Result<PolicyRule, PolicyError> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::allow_rule => Ok(PolicyRule::Allow(parse_allow_rule(inner)?)),
        Rule::deny_rule  => Ok(PolicyRule::Deny(parse_deny_rule(inner)?)),
        r => Err(PolicyError::Parse(format!("unexpected policy rule: {:?}", r))),
    }
}

fn parse_allow_rule(pair: Pair<Rule>) -> Result<AllowRule, PolicyError> {
    let mut conditions = Vec::new();
    let mut effects    = Vec::new();
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::condition_list => conditions = parse_condition_list(child)?,
            Rule::effect_clause  => effects.push(parse_effect_clause(child)?),
            _ => {}
        }
    }
    Ok(AllowRule { conditions, effects })
}

fn parse_deny_rule(pair: Pair<Rule>) -> Result<DenyRule, PolicyError> {
    let mut conditions = Vec::new();
    let mut reason     = None;
    let mut effects    = Vec::new();
    for child in pair.into_inner() {
        match child.as_rule() {
            Rule::condition_list => conditions = parse_condition_list(child)?,
            Rule::reason_clause  => {
                reason = Some(unquote(child.into_inner().next().unwrap().as_str()));
            }
            Rule::effect_clause  => effects.push(parse_effect_clause(child)?),
            _ => {}
        }
    }
    Ok(DenyRule { conditions, reason, effects })
}

fn parse_effect_clause(pair: Pair<Rule>) -> Result<EffectDecl, PolicyError> {
    let effect = pair.into_inner().next().unwrap();
    let inner_effect = effect.into_inner().next().unwrap();
    match inner_effect.as_rule() {
        Rule::redact_effect => {
            let mut i = inner_effect.into_inner();
            Ok(EffectDecl::Redact {
                selector:   unquote(i.next().unwrap().as_str()),
                classifier: unquote(i.next().unwrap().as_str()),
            })
        }
        Rule::mask_effect => {
            let mut i = inner_effect.into_inner();
            Ok(EffectDecl::Mask {
                selector:    unquote(i.next().unwrap().as_str()),
                pattern:     unquote(i.next().unwrap().as_str()),
                replacement: unquote(i.next().unwrap().as_str()),
            })
        }
        Rule::annotate_effect => {
            let mut i = inner_effect.into_inner();
            Ok(EffectDecl::Annotate {
                key:   unquote(i.next().unwrap().as_str()),
                value: unquote(i.next().unwrap().as_str()),
            })
        }
        Rule::audit_effect => {
            let level_str = inner_effect.into_inner().next().unwrap().as_str();
            let level = match level_str {
                "Critical" => AuditLevelDecl::Critical,
                "Elevated" => AuditLevelDecl::Elevated,
                "Standard" => AuditLevelDecl::Standard,
                s => return Err(PolicyError::Parse(format!("unknown audit level: {}", s))),
            };
            Ok(EffectDecl::Audit { level })
        }
        r => Err(PolicyError::Parse(format!("unexpected effect: {:?}", r))),
    }
}

fn unquote(s: &str) -> String {
    s[1..s.len() - 1].to_string()
}
