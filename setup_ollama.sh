#!/bin/bash
# Quick start guide for Ollama AI integration
# Run this file to check/install Ollama

set -e

echo "=========================================="
echo "🤖 Ollama Setup Guide"
echo "=========================================="
echo ""

# Check if Ollama is installed
if command -v ollama &> /dev/null; then
    echo "✅ Ollama is installed"
    ollama --version
else
    echo "❌ Ollama is NOT installed"
    echo ""
    echo "📥 Installation Instructions:"
    echo ""
    echo "For macOS/Linux:"
    echo "  curl -fsSL https://ollama.ai/install.sh | sh"
    echo ""
    echo "For Windows:"
    echo "  Download from https://ollama.ai/download"
    echo ""
    exit 1
fi

echo ""
echo "=========================================="
echo "📦 Checking for gemma:2b model"
echo "=========================================="
echo ""

# Check if model exists (by trying to show its info)
if ollama list | grep -q "gemma:2b"; then
    echo "✅ gemma:2b model is installed"
else
    echo "❌ gemma:2b model NOT found"
    echo ""
    echo "📥 Installing gemma:2b..."
    echo ""
    ollama pull gemma:2b
    echo ""
    echo "✅ Model installed successfully!"
fi

echo ""
echo "=========================================="
echo "🚀 Starting Ollama Server"
echo "=========================================="
echo ""
echo "Run this command in a separate terminal:"
echo ""
echo "  ollama serve"
echo ""
echo "Then in another terminal, run:"
echo ""
echo "  python test_ai.py"
echo ""
echo "To verify AI is working!"
echo ""
