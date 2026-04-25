// SPDX-License-Identifier: Apache-2.0
use crate::scan::scanner::Finding;

pub fn render(_findings: &[Finding]) {
    eprintln!(
        "HTML report is not supported. \
         Use --format json or --format terminal."
    );
}
