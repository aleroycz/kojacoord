use super::nbt::NbtTag;
use std::collections::HashMap;

pub fn parse_snbt(input: &str) -> Result<NbtTag, SnbtError> {
    let mut parser = SnbtParser::new(input);
    parser.parse_value()
}

pub fn to_snbt(tag: &NbtTag) -> String {
    match tag {
        NbtTag::End => "END".to_string(),
        NbtTag::Byte(v) => format!("{}b", v),
        NbtTag::Short(v) => format!("{}s", v),
        NbtTag::Int(v) => v.to_string(),
        NbtTag::Long(v) => format!("{}L", v),
        NbtTag::Float(v) => format!("{}f", v),
        NbtTag::Double(v) => format!("{}d", v),
        NbtTag::String(s) => format_snbt_string(s),
        NbtTag::ByteArray(arr) => {
            let items: Vec<String> = arr.iter().map(|b| format!("{}b", b)).collect();
            format!("[B;{}]", items.join(","))
        },
        NbtTag::IntArray(arr) => {
            let items: Vec<String> = arr.iter().map(|i| i.to_string()).collect();
            format!("[I;{}]", items.join(","))
        },
        NbtTag::LongArray(arr) => {
            let items: Vec<String> = arr.iter().map(|l| format!("{}L", l)).collect();
            format!("[L;{}]", items.join(","))
        },
        NbtTag::List(list) => {
            if list.is_empty() {
                "[]".to_string()
            } else {
                let items: Vec<String> = list.iter().map(to_snbt).collect();
                format!("[{}]", items.join(","))
            }
        },
        NbtTag::Compound(compound) => {
            if compound.is_empty() {
                "{}".to_string()
            } else {
                let items: Vec<String> = compound
                    .iter()
                    .map(|(k, v)| format!("{}:{}", k, to_snbt(v)))
                    .collect();
                format!("{{{}}}", items.join(","))
            }
        },
    }
}

fn format_snbt_string(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{}\"", escaped)
}

struct SnbtParser {
    input: Vec<char>,
    pos: usize,
}

impl SnbtParser {
    fn new(input: &str) -> Self {
        Self {
            input: input.chars().collect(),
            pos: 0,
        }
    }

    fn current(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    fn skip_whitespace(&mut self) {
        while let Some(c) = self.current() {
            if c.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<NbtTag, SnbtError> {
        self.skip_whitespace();

        match self.current() {
            Some('{') => self.parse_compound(),
            Some('[') => self.parse_list_or_array(),
            Some('"') | Some('\'') => self.parse_quoted_string().map(NbtTag::String),
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => self.parse_number(),
            Some(c) if c.is_alphabetic() || c == '_' => self.parse_unquoted_string(),
            Some(c) => Err(SnbtError::UnexpectedChar(c, self.pos)),
            None => Err(SnbtError::UnexpectedEof),
        }
    }

    fn parse_compound(&mut self) -> Result<NbtTag, SnbtError> {
        self.advance();
        self.skip_whitespace();

        let mut map = HashMap::new();

        if self.current() == Some('}') {
            self.advance();
            return Ok(NbtTag::Compound(map));
        }

        loop {
            self.skip_whitespace();

            let key = match self.current() {
                Some('"') | Some('\'') => self.parse_quoted_string()?,
                Some(c) if c.is_alphabetic() || c == '_' => self.parse_identifier()?,
                Some('}') => {
                    self.advance();
                    return Ok(NbtTag::Compound(map));
                },
                Some(c) => return Err(SnbtError::UnexpectedChar(c, self.pos)),
                None => return Err(SnbtError::UnexpectedEof),
            };

            self.skip_whitespace();

            if self.current() != Some(':') {
                return Err(SnbtError::Expected(':', self.pos));
            }
            self.advance();

            let value = self.parse_value()?;
            map.insert(key, value);

            self.skip_whitespace();

            match self.current() {
                Some(',') => {
                    self.advance();
                    continue;
                },
                Some('}') => {
                    self.advance();
                    return Ok(NbtTag::Compound(map));
                },
                Some(c) => return Err(SnbtError::UnexpectedChar(c, self.pos)),
                None => return Err(SnbtError::UnexpectedEof),
            }
        }
    }

    fn parse_list_or_array(&mut self) -> Result<NbtTag, SnbtError> {
        self.advance();
        self.skip_whitespace();

        if let Some(type_char) = self.current() {
            if (type_char == 'B' || type_char == 'I' || type_char == 'L')
                && self.input.get(self.pos + 1) == Some(&';')
            {
                return self.parse_typed_array(type_char);
            }
        }

        let mut list = Vec::new();

        if self.current() == Some(']') {
            self.advance();
            return Ok(NbtTag::List(list));
        }

        loop {
            let value = self.parse_value()?;
            list.push(value);

            self.skip_whitespace();

            match self.current() {
                Some(',') => {
                    self.advance();
                    self.skip_whitespace();
                    continue;
                },
                Some(']') => {
                    self.advance();
                    return Ok(NbtTag::List(list));
                },
                Some(c) => return Err(SnbtError::UnexpectedChar(c, self.pos)),
                None => return Err(SnbtError::UnexpectedEof),
            }
        }
    }

    fn parse_typed_array(&mut self, type_char: char) -> Result<NbtTag, SnbtError> {
        self.advance();
        self.advance();
        self.skip_whitespace();

        match type_char {
            'B' => {
                let mut arr = Vec::new();
                if self.current() != Some(']') {
                    loop {
                        let value = self.parse_number()?;
                        match value {
                            NbtTag::Byte(b) => arr.push(b),
                            NbtTag::Int(i) => arr.push(i as i8),
                            _ => return Err(SnbtError::TypeMismatch),
                        }

                        self.skip_whitespace();
                        match self.current() {
                            Some(',') => self.advance(),
                            Some(']') => break,
                            Some(c) => return Err(SnbtError::UnexpectedChar(c, self.pos)),
                            None => return Err(SnbtError::UnexpectedEof),
                        }
                        self.skip_whitespace();
                    }
                }
                self.advance();
                Ok(NbtTag::ByteArray(arr))
            },
            'I' => {
                let mut arr = Vec::new();
                if self.current() != Some(']') {
                    loop {
                        let value = self.parse_number()?;
                        match value {
                            NbtTag::Int(i) => arr.push(i),
                            _ => return Err(SnbtError::TypeMismatch),
                        }

                        self.skip_whitespace();
                        match self.current() {
                            Some(',') => self.advance(),
                            Some(']') => break,
                            Some(c) => return Err(SnbtError::UnexpectedChar(c, self.pos)),
                            None => return Err(SnbtError::UnexpectedEof),
                        }
                        self.skip_whitespace();
                    }
                }
                self.advance();
                Ok(NbtTag::IntArray(arr))
            },
            'L' => {
                let mut arr = Vec::new();
                if self.current() != Some(']') {
                    loop {
                        let value = self.parse_number()?;
                        match value {
                            NbtTag::Long(l) => arr.push(l),
                            NbtTag::Int(i) => arr.push(i as i64),
                            _ => return Err(SnbtError::TypeMismatch),
                        }

                        self.skip_whitespace();
                        match self.current() {
                            Some(',') => self.advance(),
                            Some(']') => break,
                            Some(c) => return Err(SnbtError::UnexpectedChar(c, self.pos)),
                            None => return Err(SnbtError::UnexpectedEof),
                        }
                        self.skip_whitespace();
                    }
                }
                self.advance();
                Ok(NbtTag::LongArray(arr))
            },
            _ => unreachable!(),
        }
    }

    fn parse_quoted_string(&mut self) -> Result<String, SnbtError> {
        let quote = self.current().ok_or(SnbtError::UnexpectedEof)?;
        self.advance();

        let mut result = String::new();
        let mut escaped = false;

        while let Some(c) = self.current() {
            if escaped {
                match c {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '\\' => result.push('\\'),
                    '\'' => result.push('\''),
                    '"' => result.push('"'),
                    _ => {
                        result.push('\\');
                        result.push(c);
                    },
                }
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == quote {
                self.advance();
                return Ok(result);
            } else {
                result.push(c);
            }
            self.advance();
        }

        Err(SnbtError::UnterminatedString)
    }

    fn parse_identifier(&mut self) -> Result<String, SnbtError> {
        let mut result = String::new();

        while let Some(c) = self.current() {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                result.push(c);
                self.advance();
            } else {
                break;
            }
        }

        Ok(result)
    }

    fn parse_unquoted_string(&mut self) -> Result<NbtTag, SnbtError> {
        let s = self.parse_identifier()?;

        match s.as_str() {
            "true" => Ok(NbtTag::Byte(1)),
            "false" => Ok(NbtTag::Byte(0)),
            _ => Ok(NbtTag::String(s)),
        }
    }

    fn parse_number(&mut self) -> Result<NbtTag, SnbtError> {
        let mut num_str = String::new();
        let mut has_dot = false;

        if let Some(sign @ ('+' | '-')) = self.current() {
            num_str.push(sign);
            self.advance();
        }

        while let Some(c) = self.current() {
            if c.is_ascii_digit() {
                num_str.push(c);
                self.advance();
            } else if c == '.' && !has_dot {
                has_dot = true;
                num_str.push(c);
                self.advance();
            } else {
                break;
            }
        }

        let type_suffix = self.current();
        if let Some(suffix @ ('b' | 'B' | 's' | 'S' | 'l' | 'L' | 'f' | 'F' | 'd' | 'D')) =
            type_suffix
        {
            self.advance();

            return match suffix.to_ascii_lowercase() {
                'b' => num_str
                    .parse::<i8>()
                    .map(NbtTag::Byte)
                    .map_err(|_| SnbtError::InvalidNumber(num_str)),
                's' => num_str
                    .parse::<i16>()
                    .map(NbtTag::Short)
                    .map_err(|_| SnbtError::InvalidNumber(num_str)),
                'l' => num_str
                    .parse::<i64>()
                    .map(NbtTag::Long)
                    .map_err(|_| SnbtError::InvalidNumber(num_str)),
                'f' => num_str
                    .parse::<f32>()
                    .map(NbtTag::Float)
                    .map_err(|_| SnbtError::InvalidNumber(num_str)),
                'd' => num_str
                    .parse::<f64>()
                    .map(NbtTag::Double)
                    .map_err(|_| SnbtError::InvalidNumber(num_str)),
                _ => unreachable!(),
            };
        }

        if has_dot {
            num_str
                .parse::<f64>()
                .map(NbtTag::Double)
                .map_err(|_| SnbtError::InvalidNumber(num_str))
        } else {
            num_str
                .parse::<i32>()
                .map(NbtTag::Int)
                .map_err(|_| SnbtError::InvalidNumber(num_str))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnbtError {
    #[error("Unexpected character '{0}' at position {1}")]
    UnexpectedChar(char, usize),

    #[error("Unexpected end of input")]
    UnexpectedEof,

    #[error("Expected '{0}' at position {1}")]
    Expected(char, usize),

    #[error("Unterminated string")]
    UnterminatedString,

    #[error("Invalid number: {0}")]
    InvalidNumber(String),

    #[error("Type mismatch in array")]
    TypeMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_compound() {
        let result = parse_snbt("{}");
        assert!(result.is_ok());
        match result.unwrap() {
            NbtTag::Compound(c) => assert!(c.is_empty()),
            _ => panic!("Expected compound"),
        }
    }

    #[test]
    fn test_parse_simple_compound() {
        let result = parse_snbt("{name:\"Test\",value:123}");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_list() {
        let result = parse_snbt("[1,2,3,4]");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_byte_array() {
        let result = parse_snbt("[B;1b,2b,3b]");
        assert!(result.is_ok());
        match result.unwrap() {
            NbtTag::ByteArray(arr) => assert_eq!(arr, vec![1, 2, 3]),
            _ => panic!("Expected byte array"),
        }
    }

    #[test]
    fn test_to_snbt() {
        let tag = NbtTag::Int(123);
        assert_eq!(to_snbt(&tag), "123");

        let tag = NbtTag::String("test".to_string());
        assert_eq!(to_snbt(&tag), "\"test\"");
    }
}
