use scraper::{Html, Selector};
use std::collections::HashSet;
use url::Url;

use crate::scanner::traits::{FormData, FormField, InjectionPoint, ParamLocation};

pub fn extract_forms(html: &str, page_url: &Url) -> Vec<FormData> {
    let document = Html::parse_document(html);
    let form_selector = Selector::parse("form").unwrap();
    let input_selector = Selector::parse("input, select, textarea").unwrap();

    let mut forms = Vec::new();
    let mut inputs_in_forms = HashSet::new();

    // Phase 1: Extract traditional <form> elements
    for form_el in document.select(&form_selector) {
        let action = form_el.value().attr("action").unwrap_or("");

        let action_url = if action.is_empty() || action == "#" {
            page_url.to_string()
        } else if let Ok(resolved) = page_url.join(action) {
            resolved.to_string()
        } else {
            page_url.to_string()
        };

        let method = form_el
            .value()
            .attr("method")
            .unwrap_or("POST")
            .to_uppercase();

        let enctype = form_el.value().attr("enctype").map(|s| s.to_string());

        let mut fields = Vec::new();

        for input_el in form_el.select(&input_selector) {
            // Track which inputs are inside forms
            let input_id = input_el.value().attr("id").unwrap_or("").to_string();
            let input_name = input_el.value().attr("name").unwrap_or("").to_string();
            if !input_name.is_empty() {
                inputs_in_forms.insert(input_name.clone());
            }
            if !input_id.is_empty() {
                inputs_in_forms.insert(input_id);
            }

            let name = if !input_name.is_empty() {
                input_name
            } else {
                continue;
            };

            let field_type = input_el
                .value()
                .attr("type")
                .unwrap_or("text")
                .to_lowercase();

            if field_type == "submit" || field_type == "button" || field_type == "image" {
                continue;
            }

            let value = input_el.value().attr("value").map(|v| v.to_string());
            let required = input_el.value().attr("required").is_some();

            fields.push(FormField {
                name,
                field_type,
                value,
                required,
            });
        }

        if !fields.is_empty() {
            forms.push(FormData {
                action: action_url,
                method,
                fields,
                enctype,
            });
        }
    }

    // Phase 2: Find standalone inputs NOT inside any <form> (common in React/SPA apps)
    let mut standalone_fields = Vec::new();

    for input_el in document.select(&input_selector) {
        let field_type = input_el
            .value()
            .attr("type")
            .unwrap_or("text")
            .to_lowercase();

        // Skip non-injectable types
        if field_type == "submit"
            || field_type == "button"
            || field_type == "image"
            || field_type == "hidden"
            || field_type == "checkbox"
            || field_type == "radio"
            || field_type == "file"
        {
            continue;
        }

        // Only target text-like inputs
        let is_injectable = matches!(
            field_type.as_str(),
            "text" | "email" | "search" | "url" | "tel" | "password" | "number" | "textarea"
        ) || input_el.value().name() == "textarea";

        if !is_injectable {
            continue;
        }

        // Determine a name: prefer name attr, then id, then placeholder, then type
        let name = input_el
            .value()
            .attr("name")
            .filter(|n| !n.is_empty())
            .or_else(|| input_el.value().attr("id").filter(|n| !n.is_empty()))
            .or_else(|| input_el.value().attr("placeholder").filter(|n| !n.is_empty()))
            .unwrap_or(&field_type)
            .to_string();

        // Skip if this input was already captured inside a <form>
        if inputs_in_forms.contains(&name) {
            continue;
        }

        let value = input_el.value().attr("value").map(|v| v.to_string());
        let required = input_el.value().attr("required").is_some();

        standalone_fields.push(FormField {
            name,
            field_type,
            value,
            required,
        });
    }

    // Group standalone inputs as a synthetic form targeting the current page
    if !standalone_fields.is_empty() {
        forms.push(FormData {
            action: page_url.to_string(),
            method: "POST".to_string(),
            fields: standalone_fields,
            enctype: None,
        });
    }

    forms
}

pub fn forms_to_injection_points(forms: &[FormData]) -> Vec<InjectionPoint> {
    let mut points = Vec::new();

    for form in forms {
        let location = if form.method == "POST" {
            ParamLocation::Body
        } else {
            ParamLocation::Query
        };

        for field in &form.fields {
            points.push(InjectionPoint {
                name: field.name.clone(),
                location: location.clone(),
                original_value: field.value.clone(),
                context: None,
            });
        }
    }

    points
}
