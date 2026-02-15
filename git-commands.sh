#!/bin/bash

# Git Commands for CLI Tool PR
# Execute these commands to commit and push your changes

echo "🎯 Starting Git workflow for CLI Tool PR..."

# 1. Stage all new CLI files
echo "📁 Staging CLI files..."
git add src/cli/
git add docs/CLI-GUIDE.md docs/CLI-IMPLEMENTATION.md
git add examples/sample.log

# 2. Stage modified files
echo "📝 Staging modified files..."
git add package.json pnpm-lock.yaml
git add README.md CONTRIBUTING.md

# 3. Check what will be committed
echo "🔍 Files to be committed:"
git status --short

# 4. Create commit with comprehensive message
echo "💾 Creating commit..."
git commit -m "feat: add comprehensive CLI tool for log management and analysis

Implements a full-featured command-line interface for Logixia that enables
developers to manage, analyze, and monitor logs directly from the terminal.

Features:
- analyze: Log analysis with level filtering and time-based queries (--level, --last 24h)
- stats: Statistical analysis with visual bar charts and distribution percentages
- search: Query logs using field:value syntax with multiple output formats
- export: Export logs to CSV/JSON with field selection
- tail: Real-time log monitoring with filtering and syntax highlighting

Technical Implementation:
- Built with Commander.js v11 for robust CLI argument parsing
- Color-coded output using chalk v5 for better readability
- Stream-based file processing for efficient memory usage
- TypeScript with strict type checking throughout
- Comprehensive test suite with 12/12 tests passing

Documentation:
- Added detailed CLI section to README.md
- Created CLI-GUIDE.md for quick reference
- Created CLI-IMPLEMENTATION.md for technical details
- Updated CONTRIBUTING.md with CLI development guidelines

Files Added:
- src/cli/index.ts, utils.ts
- src/cli/commands/{analyze,stats,search,export,tail}.ts
- src/cli/__tests__/{analyze,commands}.test.ts
- docs/CLI-GUIDE.md, docs/CLI-IMPLEMENTATION.md
- examples/sample.log

Files Modified:
- package.json, pnpm-lock.yaml
- README.md, CONTRIBUTING.md

Tested:
- 12/12 unit tests passing
- All commands manually tested with sample data
- TypeScript compilation successful
- No build errors or warnings

Closes #[REPLACE_WITH_ISSUE_NUMBER]"

# 5. Create feature branch (if needed)
echo "🌿 Creating/switching to feature branch..."
BRANCH_NAME="feature/cli-tool"
git checkout -b $BRANCH_NAME 2>/dev/null || git checkout $BRANCH_NAME

# 6. Push to remote
echo "🚀 Pushing to remote..."
git push -u origin $BRANCH_NAME

echo ""
echo "✅ Git operations complete!"
echo ""
echo "📋 Next steps:"
echo "1. Go to GitHub and create a Pull Request"
echo "2. Use the PR description from COMMIT_AND_PR_MESSAGES.md"
echo "3. Add labels: enhancement, cli, tooling, hacktoberfest"
echo "4. Replace [ISSUE_NUMBER] with actual issue number"
echo ""
echo "Or use GitHub CLI:"
echo "gh pr create --title 'Add CLI Tool for Log Management and Analysis' --body-file COMMIT_AND_PR_MESSAGES.md --label enhancement,cli,tooling,hacktoberfest"
