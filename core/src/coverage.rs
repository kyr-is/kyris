// SPDX-License-Identifier: Apache-2.0
use kyris_types::event::{Action, AttributionMethod, CoverageState, Event};

#[must_use]
pub fn derive(action: Action, attribution_method: AttributionMethod, mode: &str) -> CoverageState {
    match action {
        Action::Think => CoverageState::Observed,
        Action::Execute | Action::Call | Action::Read | Action::Write => match attribution_method {
            AttributionMethod::Boundary | AttributionMethod::Lineage if mode == "enforce" => {
                CoverageState::Enforced
            }
            AttributionMethod::Boundary | AttributionMethod::Lineage => CoverageState::Observed,
            AttributionMethod::Unknown => CoverageState::Unknown,
        },
    }
}

pub fn derive_for_event(event: &mut Event) {
    event.coverage_state = derive(event.action, event.attribution_method, &event.mode);
}

#[must_use]
pub fn sql_expr() -> &'static str {
    "CASE \
       WHEN action = 'think' THEN 'observed' \
       WHEN attribution_method IN ('boundary', 'lineage') AND mode = 'enforce' THEN 'enforced' \
       WHEN attribution_method IN ('boundary', 'lineage') THEN 'observed' \
       ELSE 'unknown' \
     END"
}

#[cfg(test)]
#[allow(non_snake_case)]
mod tests {
    use super::*;

    #[test]
    fn testEnforcedExecute() {
        assert_eq!(
            derive(Action::Execute, AttributionMethod::Boundary, "enforce"),
            CoverageState::Enforced
        );
        assert_eq!(
            derive(Action::Call, AttributionMethod::Lineage, "enforce"),
            CoverageState::Enforced
        );
    }

    #[test]
    fn testObservedExecute() {
        assert_eq!(
            derive(Action::Execute, AttributionMethod::Lineage, "log"),
            CoverageState::Observed
        );
        assert_eq!(
            derive(Action::Execute, AttributionMethod::Boundary, "log"),
            CoverageState::Observed
        );
    }

    #[test]
    fn testUnknownAttribution() {
        assert_eq!(
            derive(Action::Execute, AttributionMethod::Unknown, "enforce"),
            CoverageState::Unknown
        );
    }

    #[test]
    fn testThinkObserved() {
        assert_eq!(
            derive(Action::Think, AttributionMethod::Lineage, "enforce"),
            CoverageState::Observed
        );
    }
}
