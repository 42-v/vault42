module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [2, 'always', [
      'feat',     // new feature
      'fix',      // bug fix
      'docs',     // documentation
      'style',    // formatting (no code change)
      'refactor', // code restructuring
      'perf',     // performance improvement
      'test',     // adding/updating tests
      'build',    // build system or deps
      'ci',       // CI/CD changes
      'chore',    // maintenance
      'revert',   // revert a commit
      'security', // security fix
      // Compliance is first-class here: docs/compliance-register.json is
      // machine-readable, coupled to the code in both directions, and gated
      // by tests that fail when the code improves past a row's claim as well
      // as when it regresses. A row moving to Met is a change to what the
      // project asserts about itself, which 'docs' would understate.
      'compliance', // compliance register or claim change
    ]],
    'subject-case': [0], // allow any case
    // conventional-commits-parser treats any body line matching `token: value`
    // as a footer, so ordinary prose that happens to start a line with a word
    // and a colon ("directly: no audit row was written") is parsed as a footer
    // missing its leading blank line. The rule cannot tell that apart from a
    // real footer, and this repo writes full prose bodies rather than footers,
    // so it fired on 25 otherwise-correct messages and on nothing else.
    'footer-leading-blank': [0],
  },
};
