# Contributing to CloudGuardStack

Thank you for your interest in contributing to CloudGuardStack! We welcome contributions from the community to help improve this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Feature Requests](#feature-requests)
- [License](#license)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
   ```bash
   git clone https://github.com/your-username/cloud_guard_stack.git
   cd cloud_guard_stack
   ```
3. Set up your development environment (see below)
4. Create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```
5. Make your changes
6. Run tests and verify your changes
7. Commit and push to your fork
8. Open a pull request

## Development Environment

### Prerequisites

- Python 3.9+
- Terraform 1.5.0+
- Docker 20.10+
- Pre-commit hooks

### Setup

1. Install development dependencies:
   ```bash
   pip install -e .[dev]
   ```

2. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

3. Run tests:
   ```bash
   pytest tests/
   ```

## Code Style

- Python code follows [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Terraform code follows the [Terraform Style Conventions](https://www.terraform.io/language/syntax/style)
- Documentation follows [Google Style Python Docstrings](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings)

## Pull Request Process

1. Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2. Update the README.md with details of changes to the interface, including new environment variables, exposed ports, useful file locations, and container parameters.
3. Increase the version numbers in any examples files and the README.md to the new version that this Pull Request would represent.
4. Your pull request should target the `main` branch.
5. Ensure all tests pass and add tests for new functionality.
6. Update documentation as needed.

## Reporting Issues

When reporting issues, please include:

- Description of the problem
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment details (OS, Python version, etc.)
- Any relevant logs or error messages

## Feature Requests

We welcome feature requests! Please open an issue with:

- A clear description of the feature
- Use cases for the feature
- Any alternative solutions you've considered
- Additional context or screenshots if applicable

## License

By contributing, you agree that your contributions will be licensed under the project's [LICENSE](LICENSE) file.