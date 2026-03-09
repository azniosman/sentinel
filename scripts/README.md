# Scripts Directory

This directory contains utility scripts for the AI-SOC platform.

## Available Scripts

Currently, this directory is empty. Scripts can be added here for:

- Automated maintenance tasks
- Backup and restore operations
- Custom data import/export
- Development utilities
- Testing automation

## Example Script Template

```bash
#!/bin/bash
# Example AI-SOC utility script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"

echo "AI-SOC Utility Script"
echo "====================="

# Add your script logic here
```

## Contributing Scripts

When adding scripts:

1. Make them executable: `chmod +x script_name.sh`
2. Add a header with description and usage
3. Use `set -e` for error handling
4. Document dependencies in comments
5. Test thoroughly before committing
