#!/bin/bash

# Quick Setup Script for Prompt Injection Testing Suite
# This script helps you get started quickly

echo "Prompt Injection Testing Suite - Quick Setup"
echo "=================================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version found"
echo ""

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
if [ $? -eq 0 ]; then
    echo "✓ Virtual environment created"
else
    echo "✗ Failed to create virtual environment"
    exit 1
fi
echo ""

# Activate virtual environment
echo "To activate the virtual environment, run:"
echo "  source venv/bin/activate  (Linux/Mac)"
echo "  venv\\Scripts\\activate     (Windows)"
echo ""

# Install dependencies
echo "After activating, install dependencies with:"
echo "  pip install -r requirements.txt"
echo ""

# Quick test
echo "Then run the demo to test everything works:"
echo "  python examples/demo.py"
echo ""

echo "=================================================="
echo "🎉 Setup guide complete!"
echo ""
echo "Quick Start Commands:"
echo "  1. source venv/bin/activate"
echo "  2. pip install -r requirements.txt"
echo "  3. python examples/demo.py"
echo ""
echo "For more info, see README.md"
