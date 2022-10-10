use ockam_core::compat::collections::BTreeMap;
use core::fmt;

// TODO: Proper error
#[derive(Debug)]
pub enum Error {
    Unbound(String),
    UnknownFn(String),
    InvalidType,
    Parser(s_expr::ParserError),
    NotSupported(&'static str),
    Overflow
}

impl From<s_expr::ParserError> for Error {
    fn from(e: s_expr::ParserError) -> Self {
        Self::Parser(e)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Env(BTreeMap<String, Expr>);

impl Env {
    pub fn new() -> Self {
        Env(BTreeMap::new())
    }

    pub fn get(&self, k: &str) -> Result<&Expr, Error> {
        self.0.get(k).ok_or_else(|| Error::Unbound(k.to_string()))
    }

    pub fn put<K: Into<String>, E: Into<Expr>>(&mut self, k: K, v: E) -> &mut Self {
        self.0.insert(k.into(), v.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Expr {
    Unit,
    Str(String),
    Int(i64),
    Bool(bool),
    Var(String),
    List(Vec<Expr>),
    Vec(Vec<Expr>)
}

impl From<bool> for Expr {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

impl From<i64> for Expr {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}

pub fn t() -> Expr {
    Expr::Bool(true)
}

pub fn f() -> Expr {
    Expr::Bool(false)
}

pub fn int<I: Into<i64>>(i: I) -> Expr {
    Expr::Int(i.into())
}

pub fn var<S: Into<String>>(s: S) -> Expr {
    Expr::Var(s.into())
}

pub fn vec<T: IntoIterator<Item = Expr>>(xs: T) -> Expr {
    Expr::Vec(xs.into_iter().collect())
}

pub fn str<S: Into<String>>(s: S) -> Expr {
    Expr::Str(s.into())
}

pub fn parse(s: &str) -> Result<Expr, Error> {
    Expr::try_from(s)
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expr::Str(s)      => write!(f, "{s:?}"),
            Expr::Int(i)      => write!(f, "{i}"),
            Expr::Bool(true)  => f.write_str("true"),
            Expr::Bool(false) => f.write_str("false"),
            Expr::Var(v)      => f.write_str(v),
            Expr::List(es)    => {
                let mut p = s_expr::Printer::default();
                p.open(s_expr::GroupKind::Paren);
                for e in es {
                    p.text(&e.to_string())
                }
                p.close(s_expr::GroupKind::Paren);
                f.write_str(&p.to_string())
            }
            Expr::Vec(es) => {
                let mut p = s_expr::Printer::default();
                p.open(s_expr::GroupKind::Bracket);
                for e in es {
                    p.text(&e.to_string())
                }
                p.close(s_expr::GroupKind::Bracket);
                f.write_str(&p.to_string())
            }
            Expr::Unit => f.write_str("()")
        }
    }
}

impl TryFrom<&str> for Expr {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut parser = s_expr::Parser::new(value);
        while let Some(e) = parser.next()? {
            if let Some(x) = Expr::from_element(&e.inner)? {
                return Ok(x)
            }
        }
        Ok(Expr::Unit)
    }
}

impl Expr {
    pub fn eval(&self, env: &Env) -> Result<Expr, Error> {
        match self {
            Expr::Var(name) => env.get(name).cloned(),
            Expr::List(es)  => match &es[..] {
                []                    => Ok(Expr::Unit),
                [Expr::Var(name), ..] => {
                    match name.as_str() {
                        "and" => eval_and(&es[1..], env),
                        "or"  => eval_or(&es[1..], env),
                        "not" => eval_not(&es[1..], env),
                        "if"  => eval_if(&es[1..], env),
                        "+"   => eval_arith(&es[1..], env, Some(0), i64::checked_add),
                        "*"   => eval_arith(&es[1..], env, Some(1), i64::checked_mul),
                        "-"   => eval_arith(&es[1..], env, None, i64::checked_sub),
                        "/"   => eval_arith(&es[1..], env, None, i64::checked_div),
                        "in" | "member" => eval_in(&es[1..], env),
                        "="  | "eq?" => eval_eq(&es[1..], env),
                        "!=" | "ne?" => eval_ne(&es[1..], env),
                        _     => return Err(Error::UnknownFn(name.to_string()))
                    }
                }
                _ => Err(Error::InvalidType)
            }
            expr => Ok(expr.clone())
        }
    }

    fn from_element(value: &s_expr::Element<'_>) -> Result<Option<Self>, Error> {
        use s_expr::{Element, Atom, GroupKind};
        match value {
            Element::Atom(a) => match a {
                Atom::String(s)   => Ok(Some(Expr::Str(s.to_string()))),
                Atom::Integral(i) => Ok(Some(Expr::Int(i64::from(i.to_u32().unwrap())))),
                Atom::Ident(i)    => match *i {
                    "true"  => Ok(Some(Expr::Bool(true))),
                    "false" => Ok(Some(Expr::Bool(false))),
                    _       => Ok(Some(Expr::Var(i.to_string())))
                }
                Atom::Decimal(i)  => Err(Error::NotSupported("decimal")),
                Atom::Bytes(i)    => Err(Error::NotSupported("bytes"))
            }
            Element::Comment(_) => Ok(None),
            Element::Group(GroupKind::Paren, list) => {
                let mut xs = Vec::new();
                for x in list {
                    if let Some(x) = Expr::from_element(&x.inner)? {
                        xs.push(x)
                    }
                }
                Ok(Some(Expr::List(xs)))
            }
            Element::Group(GroupKind::Bracket, vec) => {
                let mut xs = Vec::new();
                for x in vec {
                    if let Some(x) = Expr::from_element(&x.inner)? {
                        xs.push(x)
                    }
                }
                Ok(Some(Expr::Vec(xs)))
            }
            Element::Group(GroupKind::Brace, _) => Err(Error::NotSupported("braces"))
        }
    }

    pub fn is_true(&self) -> bool {
        matches!(self, Expr::Bool(true))
    }

    pub fn is_false(&self) -> bool {
        matches!(self, Expr::Bool(false))
    }
}

fn eval_and(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    for e in expr {
        match e.eval(env)? {
            Expr::Bool(true)  => continue,
            Expr::Bool(false) => return Ok(Expr::Bool(false)),
            other             => return Err(Error::InvalidType)
        }
    }
    Ok(Expr::Bool(true))
}

fn eval_or(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    for e in expr {
        match e.eval(env)? {
            Expr::Bool(true)  => return Ok(Expr::Bool(true)),
            Expr::Bool(false) => continue,
            other             => return Err(Error::InvalidType)
        }
    }
    Ok(Expr::Bool(false))

}

fn eval_if(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    match expr {
        [test, t, f] => match test.eval(env)? {
            Expr::Bool(true)  => t.eval(env),
            Expr::Bool(false) => f.eval(env),
            other             => Err(Error::InvalidType)
        }
        other => Err(Error::InvalidType)
    }
}

fn eval_not(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    if expr.len() != 2 {
        return Err(Error::InvalidType)
    }
    match expr[1].eval(env)? {
        Expr::Bool(b) => Ok(Expr::Bool(!b)),
        other         => Err(Error::InvalidType)
    }
}

fn eval_arith<F>(expr: &[Expr], env: &Env, z: Option<i64>, f: F) -> Result<Expr, Error>
where
    F: Fn(i64, i64) -> Option<i64>
{
    match expr {
        []      => z.ok_or(Error::InvalidType).map(Expr::Int),
        [a, ..] => {
            if let Expr::Int(mut i) = a.eval(env)? {
                for e in &expr[1..] {
                    match e.eval(env)? {
                        Expr::Int(j) => i = f(i, j).ok_or(Error::Overflow)?,
                        other        => return Err(Error::InvalidType)
                    }
                }
                Ok(Expr::Int(i))
            } else {
                return Err(Error::InvalidType)
            }
        }
    }
}

fn eval_eq(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    if let Some(a) = expr.first() {
        let x = a.eval(env)?;
        for e in expr.iter().skip(1) {
            let y = e.eval(env)?;
            if x != y {
                return Ok(Expr::Bool(false))
            }
        }
    }
    Ok(Expr::Bool(true))
}

fn eval_ne(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    if let Expr::Bool(b) = eval_eq(expr, env)? {
        Ok(Expr::Bool(!b))
    } else {
        Err(Error::InvalidType)
    }
}

fn eval_in(expr: &[Expr], env: &Env) -> Result<Expr, Error> {
    if expr.len() != 2 {
        return Err(Error::InvalidType)
    }
    let a = expr[0].eval(env)?;
    if let Expr::Vec(vs) = expr[1].eval(env)? {
        Ok(Expr::Bool(vs.contains(&a)))
    } else {
        Err(Error::InvalidType)
    }
}

#[cfg(test)]
mod tests {
    use super::{Env, Expr, str, parse};

    #[test]
    fn hello1() {
        const S: &str = r#"
            (and (= subject.name "foo")
                 (= resource.tag "blue"))
        "#;
        let expr = Expr::try_from(S).unwrap();
        let mut env = Env::new();
        env.put("subject.name", str("foo"))
           .put("resource.tag", str("blue"));
        println!("{expr} {}", expr.eval(&env).unwrap())
    }

    #[test]
    fn hello2() {
        const S: &str = r#"
            (if (= 7 (- (+ 1 2 3 4) 3)) "yes" "no")
        "#;
        let expr = Expr::try_from(S).unwrap();
        let mut env = Env::new();
        env.put("subject.name", str("foo"))
           .put("resource.tag", str("blue"));
        println!("{expr} {}", expr.eval(&env).unwrap())
    }

    #[test]
    fn hello3() {
        const S: &str = r#"
            (in subject.email resource.emails)
        "#;
        let expr = Expr::try_from(S).unwrap();
        let mut env = Env::new();
        env.put("subject.email", str("foo@example.com"))
           .put("resource.emails", parse(r#"["root@example.com" "foo@example.com"]"#).unwrap());
        println!("{expr} {}", expr.eval(&env).unwrap())
    }
}
