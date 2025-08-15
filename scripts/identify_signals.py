#!/usr/bin/env python3
"""
Signal Identification Script for MinimalPSFP-Attack-ML
Analyzes omnetpp.ini to identify key TSN/PSFP signals for targeted ML data collection.
"""

import re
import os

def extract_signals_from_ini(ini_file):
    """Extract all configured signal recording patterns from omnetpp.ini"""
    
    if not os.path.exists(ini_file):
        print(f"ERROR: {ini_file} not found!")
        return []
    
    signals = []
    
    with open(ini_file, 'r') as f:
        content = f.read()
    
    # Find all result-recording-modes patterns
    patterns = [
        r'\*\*\.([^:]+):vector\.result-recording-modes',
        r'\*\*\.([^:]+):count\.result-recording-modes',
        r'\*\*\.([^:]+):histogram\.result-recording-modes'
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.MULTILINE)
        signals.extend(matches)
    
    # Remove duplicates and sort
    return sorted(list(set(signals)))

def main():
    """Main function to analyze signals and generate DataCollector code"""
    
    print("🔍 TSN/PSFP Signal Analysis for ML Data Collection")
    print("=" * 60)
    
    # Extract signals from omnetpp.ini
    ini_file = "simulations/omnetpp.ini"
    signals = extract_signals_from_ini(ini_file)
    
    print(f"📊 Found {len(signals)} unique signals in {ini_file}")
    
    # Show key signals we want for ML
    ml_signals = [
        "bridging.streamFilter.ingress.meter[*].committedConformingPackets",
        "bridging.streamFilter.ingress.meter[*].committedNonConformingPackets",
        "app[*].endToEndDelay",
        "queue.queueLength",
        "gptp.clockServo.offsetNanoseconds",
        "app[*].packetSent",
        "app[*].packetReceived"
    ]
    
    print(f"\n🎯 Selected {len(ml_signals)} Key Signals for ML:")
    for i, signal in enumerate(ml_signals, 1):
        print(f"  {i}. {signal}")
    
    # Show all found signals
    print(f"\n📋 All found signals ({len(signals)}):")
    for signal in signals:
        print(f"  - {signal}")
    
    print(f"\n✅ Analysis complete!")

if __name__ == "__main__":
    main()
