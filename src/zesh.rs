use anyhow::anyhow;
use indoc::formatdoc;
use std::fmt;

pub struct Zesh {
    pub name: String,
    pub created_at: String,
    pub exited: bool,
    pub raw: String,
}

impl fmt::Display for Zesh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Zesh {
            name,
            created_at,
            exited,
            raw,
        } = self;

        let s = formatdoc! {"
        {{
            name: {name}
            created_at: {created_at}
            exited: {exited}
            raw: {raw}
        }}
        "};

        write!(f, "{s}")
    }
}

impl TryFrom<&str> for Zesh {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> std::result::Result<Self, Self::Error> {
        let raw = s.to_string();
        let Some((name, rest)) = s.split_once(" ") else {
            println!("Failed to parse session list from remote zellij!");
            return Err(anyhow!("Failed to parse session list from remote zellij!"));
        };

        if name.is_empty() {
            let errmsg = "Failed to parse session name from remote zellij session list!";
            eprintln!("{errmsg}");
            return Err(anyhow!(errmsg));
        }

        if rest.is_empty() {
            let errmsg = "Unexpected end of input while parsing zellij session list!";
            eprintln!("{errmsg}");
            return Err(anyhow!(errmsg));
        }

        let Some((created_at, rest)) = rest[1..].split_once("]") else {
            eprintln!("Failed to parse session creation timestamp!");
            return Err(anyhow!("Failed to parse session creation timestamp!"));
        };

        let created_at = created_at.trim().to_string();
        let name = name.to_string();
        let rest = rest.trim();

        if rest.is_empty() {
            return Ok(Zesh {
                name,
                created_at,
                exited: false,
                raw,
            });
        }

        if rest.contains("EXITED") {
            return Ok(Zesh {
                name,
                created_at,
                exited: true,
                raw,
            });
        }

        println!("FAILED TO RETURN ZESH");

        Err(anyhow!("Failed to parse session exit status!"))
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn parse_zesh() {
        let s =
            "friendly-tiger [Created 1month 9days 13h 33m 5s ago] (EXITED - attach to resurrect)";

        let zesh = Zesh::try_from(s);
        assert!(zesh.is_ok());

        let s = "considerate-hill [Created 4s ago] ";
        let zesh = Zesh::try_from(s);
        assert!(zesh.is_ok());
    }
}
