// Copyright (c) 2023-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::fmt::{self, Write as _};
use std::sync::{Arc, OnceLock};

use crate::validate::__buffa::oneof::field_path_element::Subscript;
use crate::validate::{FieldPath, FieldPathElement, Violation as ViolationPb};

/// A rule's id, message and path, shared by its violations.
#[derive(Debug)]
pub(crate) struct RuleInfo {
    /// The rule id.
    pub id: String,
    /// The rule's message.
    pub message: String,
    /// The rule path.
    pub path: Vec<FieldPathElement>,
}

/// A single rule violation.
#[derive(Clone, Debug)]
pub(crate) struct Violation {
    rule: Arc<RuleInfo>,
    /// Overrides the rule's message.
    message: Option<String>,
    /// The path to the field.
    field: Vec<FieldPathElement>,
    for_key: bool,
    /// Rendered on first use.
    field_path: OnceLock<String>,
}

impl Violation {
    pub(crate) fn new(rule: Arc<RuleInfo>, message: Option<String>, for_key: bool) -> Self {
        Self {
            rule,
            message,
            field: Vec::new(),
            for_key,
            field_path: OnceLock::new(),
        }
    }

    /// The field path.
    pub(crate) fn field_mut(&mut self) -> &mut Vec<FieldPathElement> {
        &mut self.field
    }

    /// The id of the rule that failed, such as `string.email`, or the `id` of
    /// a custom CEL rule.
    pub(crate) fn rule_id(&self) -> &str {
        &self.rule.id
    }

    /// The human-readable message describing the failure.
    pub(crate) fn message(&self) -> &str {
        self.message.as_deref().unwrap_or(&self.rule.message)
    }

    /// The path to the field that failed, such as `user.emails[0]`.
    ///
    /// It is empty for a message-level rule, which does not apply to a field.
    pub(crate) fn field_path(&self) -> &str {
        self.field_path.get_or_init(|| path_string(&self.field))
    }

    /// The violation as a `buf.validate.Violation`.
    pub(crate) fn proto(&self) -> ViolationPb {
        let path = |elements: &[FieldPathElement]| {
            (!elements.is_empty()).then(|| FieldPath {
                elements: elements.to_vec(),
                ..Default::default()
            })
        };
        ViolationPb {
            field: path(&self.field).into(),
            rule: path(&self.rule.path).into(),
            rule_id: Some(self.rule.id.clone()),
            message: Some(self.message().to_owned()),
            for_key: self.for_key.then_some(true),
            ..Default::default()
        }
    }
}

/// Formats as `<field path>: <message>`. An empty message is replaced by
/// `[<rule id>]`, and an empty field path is omitted.
impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.field_path().is_empty() {
            write!(f, "{}: ", self.field_path())?;
        }
        match (self.message(), self.rule_id()) {
            ("", "") => f.write_str("[unknown]"),
            ("", rule_id) => write!(f, "[{rule_id}]"),
            (message, _) => f.write_str(message),
        }
    }
}

/// Formats a path as `user.emails[0]`, matching the other protovalidate
/// implementations.
fn path_string(elements: &[FieldPathElement]) -> String {
    let mut rendered = String::new();
    for (i, element) in elements.iter().enumerate() {
        let name = element.field_name.as_deref().unwrap_or_default();
        // Extension names are already bracketed, as in `[pkg.ext]`.
        if i > 0 && !name.starts_with('[') {
            rendered.push('.');
        }
        rendered.push_str(name);
        match &element.subscript {
            None => {}
            Some(Subscript::Index(index) | Subscript::UintKey(index)) => {
                let _ = write!(rendered, "[{index}]");
            }
            Some(Subscript::IntKey(key)) => {
                let _ = write!(rendered, "[{key}]");
            }
            Some(Subscript::BoolKey(key)) => {
                let _ = write!(rendered, "[{key}]");
            }
            // The key is quoted so that a key containing `.` or `]` is
            // unambiguous.
            Some(Subscript::StringKey(key)) => {
                rendered.push_str("[\"");
                for c in key.chars() {
                    match c {
                        '\\' => rendered.push_str("\\\\"),
                        '"' => rendered.push_str("\\\""),
                        '\r' => rendered.push_str("\\r"),
                        '\n' => rendered.push_str("\\n"),
                        c => rendered.push(c),
                    }
                }
                rendered.push_str("\"]");
            }
        }
    }
    rendered
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{RuleInfo, Violation};
    use crate::validate::__buffa::oneof::field_path_element::Subscript;
    use crate::validate::FieldPathElement;

    fn element(name: &str, subscript: Option<Subscript>) -> FieldPathElement {
        FieldPathElement {
            field_name: Some(name.to_owned()),
            subscript,
            ..Default::default()
        }
    }

    fn rule(rule_id: &str, message: &str, path: Vec<FieldPathElement>) -> Arc<RuleInfo> {
        Arc::new(RuleInfo {
            id: rule_id.to_owned(),
            message: message.to_owned(),
            path,
        })
    }

    fn violation(field: Vec<FieldPathElement>, message: &str, rule_id: &str) -> Violation {
        let mut violation = Violation::new(rule(rule_id, message, vec![]), None, false);
        *violation.field_mut() = field;
        violation
    }

    fn rendered(elements: Vec<FieldPathElement>) -> String {
        violation(elements, "", "").field_path().to_owned()
    }

    #[test]
    fn a_message_level_rule_has_no_path() {
        assert_eq!(
            Violation::new(rule("", "", vec![]), None, false).field_path(),
            ""
        );
        assert_eq!(rendered(vec![]), "");
    }

    #[test]
    fn nested_fields_join_with_dots() {
        assert_eq!(rendered(vec![element("user", None)]), "user");
        assert_eq!(
            rendered(vec![element("user", None), element("email", None)]),
            "user.email"
        );
        assert_eq!(
            rendered(vec![element("user", None), element("[pkg.ext]", None)]),
            "user[pkg.ext]"
        );
    }

    #[test]
    fn subscripts_follow_the_field_they_index() {
        assert_eq!(
            rendered(vec![
                element("user", None),
                element("emails", Some(Subscript::Index(2))),
            ]),
            "user.emails[2]"
        );
        assert_eq!(
            rendered(vec![element("scores", Some(Subscript::IntKey(-3)))]),
            "scores[-3]"
        );
        assert_eq!(
            rendered(vec![element("counts", Some(Subscript::UintKey(7)))]),
            "counts[7]"
        );
        assert_eq!(
            rendered(vec![element("flags", Some(Subscript::BoolKey(true)))]),
            "flags[true]"
        );
    }

    #[test]
    fn string_keys_are_quoted() {
        assert_eq!(
            rendered(vec![element(
                "attrs",
                Some(Subscript::StringKey("x\\\"\r\n".to_owned())),
            )]),
            r#"attrs["x\\\"\r\n"]"#
        );
    }

    #[test]
    fn display_prefixes_the_field_and_prefers_the_message() {
        assert_eq!(
            violation(
                vec![element("email", None)],
                "must be an email",
                "string.email"
            )
            .to_string(),
            "email: must be an email"
        );
        assert_eq!(
            violation(vec![], "first_name needs last_name", "").to_string(),
            "first_name needs last_name"
        );
    }

    #[test]
    fn display_falls_back_to_the_rule_id() {
        assert_eq!(
            violation(vec![element("email", None)], "", "string.email").to_string(),
            "email: [string.email]"
        );
        assert_eq!(violation(vec![], "", "").to_string(), "[unknown]");
    }

    #[test]
    fn the_proto_form_is_built_from_the_rule() {
        let violation = violation(vec![], "must be an email", "string.email");
        assert_eq!(violation.rule_id(), "string.email");
        let proto = violation.proto();
        assert_eq!(proto.rule_id.as_deref(), Some("string.email"));
        assert_eq!(proto.message.as_deref(), Some("must be an email"));
        assert!(proto.field.as_option().is_none());
        assert!(proto.rule.as_option().is_none());
        assert_eq!(proto.for_key, None);

        let rule_path = vec![element("string", None), element("email", None)];
        let mut violation = Violation::new(
            rule("string.email", "must be an email", rule_path.clone()),
            Some("overridden".to_owned()),
            true,
        );
        violation.field_mut().push(element("email", None));
        let proto = violation.proto();
        assert_eq!(proto.message.as_deref(), Some("overridden"));
        assert_eq!(proto.for_key, Some(true));
        assert_eq!(
            proto.field.as_option().map(|path| path.elements.clone()),
            Some(vec![element("email", None)])
        );
        assert_eq!(
            proto.rule.as_option().map(|path| path.elements.clone()),
            Some(rule_path)
        );
    }
}
