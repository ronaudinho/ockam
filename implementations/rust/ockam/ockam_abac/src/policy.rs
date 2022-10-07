use ockam_core::compat::collections::BTreeMap;
use core::fmt;

#[derive(Debug, Clone, Default)]
pub struct Env(BTreeMap<String, Val>);

impl Env {
    pub fn new() -> Self {
        Env(BTreeMap::new())
    }

    pub fn get(&self, k: &str) -> Result<&Val, Error> {
        self.0.get(k).ok_or_else(|| Error::Unbound(k.to_string()))
    }

    pub fn put<K: Into<String>>(&mut self, k: K, v: Val) -> &mut Self {
        self.0.insert(k.into(), v);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Val {
    S(String),
    I(i64),
    B(bool),
    V(String),
    C(Vec<Val>)
}

impl Val {
    pub fn contains(&self, v: &Val) -> bool {
        if let Val::C(set) = self {
            set.contains(v)
        } else {
            false
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Val::S(s)     => write!(f, "{s:?}"),
            Val::I(i)     => write!(f, "{i}"),
            Val::B(true)  => f.write_str("true"),
            Val::B(false) => f.write_str("false"),
            Val::V(v)     => f.write_str(v),
            Val::C(vs)    => {
                let mut p = s_expr::Printer::default();
                p.open(s_expr::GroupKind::Bracket);
                for v in vs {
                    p.text(&v.to_string())
                }
                p.close(s_expr::GroupKind::Bracket);
                f.write_str(&p.to_string())
            }
        }
    }
}

pub fn string<S: Into<String>>(s: S) -> Val {
    Val::S(s.into())
}

pub fn var<S: Into<String>>(s: S) -> Val {
    Val::V(s.into())
}

pub fn int(n: i64) -> Val {
    Val::I(n)
}

pub fn bool(b: bool) -> Val {
    Val::B(b)
}

pub fn set<V: IntoIterator<Item = Val>>(v: V) -> Val {
    Val::C(v.into_iter().collect())
}

#[derive(Debug, Clone)]
pub enum Cond {
    False,
    True,
    Eq(Val, Val),
    Lt(Val, Val),
    Gt(Val, Val),
    Member(Val, Val),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>)
}

// TODO: Proper error
#[derive(Debug)]
pub enum Error {
    Unbound(String)
}

impl Cond {
    #[rustfmt::skip]
    pub fn apply(&self, env: &Env) -> Result<bool, Error> {
        match self {
            Cond::True  => Ok(true),
            Cond::False => Ok(false),
            Cond::Eq(a, b) => {
                let a = if let Val::V(k) = a { env.get(k)? } else { a };
                let b = if let Val::V(k) = b { env.get(k)? } else { b };
                Ok(a == b)
            }
            Cond::Lt(a, b) => {
                let a = if let Val::V(k) = a { env.get(k)? } else { a };
                let b = if let Val::V(k) = b { env.get(k)? } else { b };
                Ok(a < b)
            }
            Cond::Gt(a, b) => {
                let a = if let Val::V(k) = a { env.get(k)? } else { a };
                let b = if let Val::V(k) = b { env.get(k)? } else { b };
                Ok(a > b)
            }
            Cond::Member(a, b) => {
                let a = if let Val::V(k) = a { env.get(k)? } else { a };
                let b = if let Val::V(k) = b { env.get(k)? } else { b };
                Ok(a.contains(b))
            }
            Cond::Not(c)  => Ok(!c.apply(env)?),
            Cond::And(cs) => {
                for c in cs {
                    if !c.apply(env)? {
                        return Ok(false)
                    }
                }
                Ok(true)
            }
            Cond::Or(cs) => {
                for c in cs {
                    if c.apply(env)? {
                        return Ok(true)
                    }
                }
                Ok(false)
            }
        }
    }

    pub fn and(self, other: Cond) -> Cond {
        Cond::And(vec![self, other])
    }

    pub fn or(self, other: Cond) -> Cond {
        Cond::Or(vec![self, other])
    }

    pub fn all(self, mut others: Vec<Cond>) -> Cond {
        others.insert(0, self);
        Cond::And(others)
    }

    pub fn any(self, mut others: Vec<Cond>) -> Cond {
        others.insert(0, self);
        Cond::Or(others)
    }
}

pub fn t() -> Cond {
    Cond::True
}

pub fn f() -> Cond {
    Cond::False
}

pub fn eq(a: Val, b: Val) -> Cond {
    Cond::Eq(a, b)
}

pub fn lt(a: Val, b: Val) -> Cond {
    Cond::Lt(a, b)
}

pub fn gt(a: Val, b: Val) -> Cond {
    Cond::Gt(a, b)
}

pub fn member(a: Val, b: Val) -> Cond {
    Cond::Member(a, b)
}

pub fn not(c: Cond) -> Cond {
    Cond::Not(c.into())
}
