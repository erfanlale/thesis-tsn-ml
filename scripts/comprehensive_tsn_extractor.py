#!/usr/bin/env python3
"""
Optimized Multi-Threaded TSN Metrics Extractor for PSFP-scenario-IntrusionML
============================================================================

Fast extraction of key TSN metrics from OMNeT++ .vec files using parallel processing:
- Throughput (ingress/egress bitrate)
- End-to-end delay metrics  
- Packet drop rates
- Queue lengths and states
- Gate states (PSFP)
- Stream-specific metrics
- Total packet counts

Optimized for multi-core systems with efficient memory usage.
Author: AI Assistant for TSN ML Research
Date: 2025-01-22 (Optimized)
"""

import os
import sys
import re
import csv
import time
import pandas as pd
from collections import defaultdict
from pathlib import Path
import argparse
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, as_completed
import psutil
import gc
import numpy as np

class OptimizedTSNExtractor:
    def __init__(self, results_dir="simulations/results", output_dir=None, max_memory_gb=8):
        self.results_dir = Path(results_dir)
        
        # Default to CSVextractions subdirectory if not specified
        if output_dir is None:
            self.output_dir = self.results_dir / "CSVextractions"
        else:
            self.output_dir = Path(output_dir)
            
        self.output_dir.mkdir(exist_ok=True)
        
        # Memory management
        self.max_memory_gb = max_memory_gb
        self.max_memory_bytes = max_memory_gb * 1024 * 1024 * 1024
        available_memory_gb = psutil.virtual_memory().available / (1024**3)
        
        print(f"🧠 Memory Management: {available_memory_gb:.1f}GB available, limit: {max_memory_gb}GB")
        
        # Performance tracking
        self.start_time = None
        self.total_files = 0
        self.completed_files = 0
        
        # Optimized metric patterns (compiled regex for speed)
        self.metric_patterns = {
            'throughput': [
                re.compile(r'.*throughput:vector.*', re.IGNORECASE),
                re.compile(r'.*bitrate:vector.*', re.IGNORECASE),
                re.compile(r'.*txBytes:vector.*', re.IGNORECASE),
                re.compile(r'.*rxBytes:vector.*', re.IGNORECASE)
            ],
            'delay': [
                re.compile(r'.*endToEndDelay:vector.*', re.IGNORECASE),
                re.compile(r'.*delay:vector.*', re.IGNORECASE),
                re.compile(r'.*queueingTime:vector.*', re.IGNORECASE)
            ],
            'drops': [
                re.compile(r'.*packetDropped:vector.*', re.IGNORECASE),
                re.compile(r'.*packetDrop:vector.*', re.IGNORECASE),
                re.compile(r'.*dropped:vector.*', re.IGNORECASE)
            ],
            'queue': [
                re.compile(r'.*queueLength:vector.*', re.IGNORECASE),
                re.compile(r'.*queueSize:vector.*', re.IGNORECASE),
                re.compile(r'.*queueBitLength:vector.*', re.IGNORECASE)
            ],
            'gates': [
                re.compile(r'.*gateState:vector.*', re.IGNORECASE),
                re.compile(r'.*transmissionGate.*:vector.*', re.IGNORECASE)
            ],
            'packets': [
                re.compile(r'.*packetSent:count.*', re.IGNORECASE),
                re.compile(r'.*packetReceived:count.*', re.IGNORECASE),
                re.compile(r'.*packetCount:vector.*', re.IGNORECASE)
            ],
            'stream': [
                re.compile(r'.*stream.*:vector.*', re.IGNORECASE),
                re.compile(r'.*conforming.*:vector.*', re.IGNORECASE),
                re.compile(r'.*nonConforming.*:vector.*', re.IGNORECASE),
                re.compile(r'.*filtered.*:vector.*', re.IGNORECASE)
            ]
        }

    def print_status(self, message, progress=None):
        """Print status with timestamp and optional progress"""
        timestamp = time.strftime("%H:%M:%S")
        if progress:
            print(f"[{timestamp}] {message} ({progress})")
        else:
            print(f"[{timestamp}] {message}")

    def get_cpu_count(self):
        """Get optimal number of processes"""
        cpu_count = mp.cpu_count()
        # Use all cores but leave one for system
        return max(1, cpu_count - 1)

def process_vec_file_worker(args):
    """TIME-SERIES EXTRACTION worker - extracts full temporal data for ML training"""
    vec_file, metric_patterns = args
    
    # Memory monitoring
    process = psutil.Process(os.getpid())
    initial_memory = process.memory_info().rss / (1024 * 1024)
    
    print(f"🔄 Processing {vec_file.name} (PID: {os.getpid()}) - TIME-SERIES MODE (Memory: {initial_memory:.1f}MB)")
    
    scenario_name = vec_file.stem.split('-')[0]
    
    # PHASE 1: Pre-scan vector definitions to identify relevant vectors
    relevant_vectors = {}
    total_vectors = 0
    
    with open(vec_file, 'r', buffering=1048576) as f:
        for line in f:
            if line.startswith('vector '):
                total_vectors += 1
                parts = line.strip().split()
                if len(parts) >= 4:
                    try:
                        vector_id = int(parts[1])
                        module = parts[2]
                        name = parts[3]
                        full_name = f"{module}.{name}".lower()
                        
                        # Pre-filter: only keep vectors that match our patterns
                        for category, patterns in metric_patterns.items():
                            for pattern in patterns:
                                if pattern.search(full_name):
                                    # Extract node info
                                    module_parts = module.split('.')
                                    node_name = module_parts[1] if len(module_parts) >= 2 else 'unknown'
                                    node_type = get_node_type_fast(node_name)
                                    
                                    relevant_vectors[vector_id] = {
                                        'category': category,
                                        'module': module,
                                        'name': name,
                                        'node_name': node_name,
                                        'node_type': node_type,
                                        'scenario': scenario_name
                                    }
                                    break
                            if vector_id in relevant_vectors:
                                break
                    except (ValueError, IndexError):
                        continue
            elif line and line[0].isdigit():
                break
    
    print(f"   🎯 Pre-filtered: {len(relevant_vectors)}/{total_vectors} relevant vectors")
    
    if not relevant_vectors:
        print(f"   ⚠️  No relevant vectors found in {vec_file.name}")
        return defaultdict(list)
    
    # PHASE 2: Extract full time-series data (as originally intended)
    file_data = defaultdict(list)
    lines_processed = 0
    data_points_collected = 0
    
    with open(vec_file, 'r', buffering=1048576) as f:
        for line in f:
            lines_processed += 1
            line = line.strip()
            
            # Progress indicator with memory monitoring
            if lines_processed % 500000 == 0:
                current_memory = process.memory_info().rss / (1024 * 1024)
                print(f"   📊 {vec_file.name}: {lines_processed//1000}k lines, {data_points_collected:,} data points (Memory: {current_memory:.1f}MB)")
                
                # Force cleanup if memory usage is too high
                if current_memory > 6000:  # 6GB per process limit
                    print(f"   🧹 High memory usage detected, forcing cleanup...")
                    gc.collect()
            
            if not line or not line[0].isdigit():
                continue
                
            try:
                parts = line.split(None, 3)
                if len(parts) >= 4:
                    vector_id = int(parts[0])
                    
                    if vector_id not in relevant_vectors:
                        continue
                    
                    event_num = int(parts[1])
                    sim_time = float(parts[2])
                    value = float(parts[3])
                    
                    vector_info = relevant_vectors[vector_id]
                    category = vector_info['category']
                    
                    file_data[category].append({
                        'scenario': scenario_name,
                        'node_name': vector_info['node_name'],
                        'node_type': vector_info['node_type'],
                        'module': vector_info['module'],
                        'metric_name': vector_info['name'],
                        'vector_id': vector_id,
                        'event_num': event_num,
                        'sim_time': sim_time,
                        'value': value
                    })
                    
                    data_points_collected += 1
                    
            except (ValueError, IndexError):
                continue
    
    print(f"✅ Completed {vec_file.name}: {lines_processed:,} lines → {data_points_collected:,} time-series points")
    return file_data


def get_node_type_fast(node_name):
    """Fast node type determination"""
    node_name_lower = node_name.lower()
    if 'camera' in node_name_lower or 'cam' in node_name_lower:
        return 'camera'
    elif 'wheel' in node_name_lower:
        return 'wheel'
    elif 'switch' in node_name_lower:
        return 'switch'
    elif 'ecu' in node_name_lower:
        return 'ecu'
    elif 'lidar' in node_name_lower:
        return 'lidar'
    elif 'attacker' in node_name_lower:
        return 'attacker'
    else:
        return 'unknown'

class OptimizedTSNExtractor:
    def __init__(self, results_dir="simulations/results", output_dir=None):
        self.results_dir = Path(results_dir)
        
        # Default to CSVextractions subdirectory
        if output_dir is None:
            self.output_dir = self.results_dir / "CSVextractions"
        else:
            self.output_dir = Path(output_dir)
            
        self.output_dir.mkdir(exist_ok=True)
        
        self.start_time = None
        self.total_files = 0
        
        # Compiled regex patterns for speed
        self.metric_patterns = {
            'throughput': [
                re.compile(r'.*throughput:vector.*', re.IGNORECASE),
                re.compile(r'.*bitrate:vector.*', re.IGNORECASE),
                re.compile(r'.*txBytes:vector.*', re.IGNORECASE),
                re.compile(r'.*rxBytes:vector.*', re.IGNORECASE)
            ],
            'delay': [
                re.compile(r'.*endToEndDelay:vector.*', re.IGNORECASE),
                re.compile(r'.*delay:vector.*', re.IGNORECASE),
                re.compile(r'.*queueingTime:vector.*', re.IGNORECASE)
            ],
            'drops': [
                re.compile(r'.*packetDropped:vector.*', re.IGNORECASE),
                re.compile(r'.*packetDrop:vector.*', re.IGNORECASE),
                re.compile(r'.*dropped:vector.*', re.IGNORECASE)
            ],
            'queue': [
                re.compile(r'.*queueLength:vector.*', re.IGNORECASE),
                re.compile(r'.*queueSize:vector.*', re.IGNORECASE),
                re.compile(r'.*queueBitLength:vector.*', re.IGNORECASE)
            ],
            'gates': [
                re.compile(r'.*gateState:vector.*', re.IGNORECASE),
                re.compile(r'.*transmissionGate.*:vector.*', re.IGNORECASE)
            ],
            'packets': [
                re.compile(r'.*packetSent:count.*', re.IGNORECASE),
                re.compile(r'.*packetReceived:count.*', re.IGNORECASE),
                re.compile(r'.*packetCount:vector.*', re.IGNORECASE)
            ],
            'stream': [
                re.compile(r'.*stream.*:vector.*', re.IGNORECASE),
                re.compile(r'.*conforming.*:vector.*', re.IGNORECASE),
                re.compile(r'.*nonConforming.*:vector.*', re.IGNORECASE),
                re.compile(r'.*filtered.*:vector.*', re.IGNORECASE)
            ]
        }

    def find_vec_files(self):
        """Find all .vec files"""
        vec_files = list(self.results_dir.glob("*.vec"))
        self.total_files = len(vec_files)
        
        # Sort by size (smallest first for better load balancing)
        vec_files.sort(key=lambda f: f.stat().st_size)
        
        print(f"\n🔍 Found {self.total_files} .vec files:")
        for i, file in enumerate(vec_files, 1):
            size_mb = file.stat().st_size / (1024*1024)
            print(f"   {i}. {file.name} ({size_mb:.1f} MB)")
        
        return vec_files

    def run_parallel_extraction(self):
        """Run optimized parallel extraction"""
        self.start_time = time.time()
        
        print("🚀 OPTIMIZED TSN METRICS EXTRACTION")
        print(f"📂 Source: {self.results_dir}")
        print(f"📂 Output: {self.output_dir}")
        
        # Find files
        vec_files = self.find_vec_files()
        if not vec_files:
            print("❌ No .vec files found!")
            return
        
        # Conservative process count to prevent Cursor crashes
        cpu_count = mp.cpu_count()
        available_memory_gb = psutil.virtual_memory().available / (1024**3)
        
        # MEMORY-FIRST approach: 2GB per process + 4GB buffer
        max_processes_by_memory = max(1, int((available_memory_gb - 4) // 2))
        num_processes = min(2, cpu_count // 4, max_processes_by_memory, len(vec_files))  # MAX 2 processes
        
        print(f"🔧 Using {num_processes} parallel processes (MEMORY-LIMITED to prevent crashes)")
        print(f"💾 Available RAM: {available_memory_gb:.1f}GB, Max usage: ~{num_processes * 2 + 4}GB")
        
        # Prepare arguments for worker processes
        worker_args = [(vec_file, self.metric_patterns) for vec_file in vec_files]
        
        # Process files in parallel - TIME-SERIES MODE
        print(f"\n⚡ Starting parallel processing - TIME-SERIES EXTRACTION...")
        all_metrics = defaultdict(list)
        completed_count = 0
        
        with ProcessPoolExecutor(max_workers=num_processes) as executor:
            # Submit all jobs
            future_to_file = {executor.submit(process_vec_file_worker, args): args[0] 
                            for args in worker_args}
            
            # Collect results as they complete
            for future in as_completed(future_to_file):
                vec_file = future_to_file[future]
                try:
                    file_data = future.result()
                    completed_count += 1
                    
                    # Merge results
                    for category, data_list in file_data.items():
                        all_metrics[category].extend(data_list)
                    
                    # Stream intermediate results to disk (for safety)
                    if completed_count % 2 == 0 or completed_count == len(vec_files):
                        self.save_intermediate_results(all_metrics, completed_count)
                    
                    elapsed = time.time() - self.start_time
                    remaining = len(vec_files) - completed_count
                    total_points = sum(len(data_list) for data_list in all_metrics.values())
                    print(f"📊 Progress: {vec_file.name} completed ({completed_count}/{len(vec_files)}). "
                          f"Remaining: {remaining} files. Elapsed: {elapsed:.1f}s. Data points: {total_points:,}")
                    
                except Exception as e:
                    print(f"❌ Error processing {vec_file.name}: {e}")
        
        # Save final time-series data
        final_output = self.save_results(all_metrics)
        
        # Clean up intermediate files automatically
        self.cleanup_intermediate_files()
        
        # Final summary
        elapsed_time = time.time() - self.start_time
        total_data_points = sum(len(data_list) for data_list in all_metrics.values())
        
        print(f"\n🎉 TIME-SERIES EXTRACTION COMPLETED!")
        print(f"   ⏱️  Total time: {elapsed_time:.1f} seconds")
        print(f"   📊 Total data points: {total_data_points:,}")
        print(f"   📁 Files processed: {len(vec_files)}")
        print(f"   💾 Output directory: {self.output_dir}")
        
        if final_output:
            print(f"   📂 Results saved to: {final_output}")
            return final_output
        else:
            print("   ❌ No data extracted!")
            return None

    def save_intermediate_results(self, all_metrics, file_count):
        """Save intermediate results to provide progress checkpoints"""
        if not all_metrics:
            return
            
        print(f"   💾 Saving intermediate results after {file_count} files...")
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        for category, data_list in all_metrics.items():
            if not data_list:
                continue
                
            # Create intermediate filename
            output_file = self.output_dir / f"tsn_metrics_{category}_partial_{timestamp}.csv"
            
            # Convert to DataFrame and sort
            df = pd.DataFrame(data_list)
            df = df.sort_values(['scenario', 'node_name', 'sim_time'])
            
            # Save to CSV (overwrite previous partial)
            df.to_csv(output_file, index=False)
        
        print(f"   ✅ Intermediate save completed ({sum(len(dl) for dl in all_metrics.values()):,} total points)")

    def save_results(self, all_metrics):
        """Save final extracted metrics to CSV files"""
        print(f"\n💾 Saving TIME-SERIES RESULTS to {self.output_dir}/")
        
        for category, data_list in all_metrics.items():
            if not data_list:
                continue
                
            # Create final filename with timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_file = self.output_dir / f"tsn_metrics_{category}_FINAL_{timestamp}.csv"
            
            # Convert to DataFrame and sort
            df = pd.DataFrame(data_list)
            df = df.sort_values(['scenario', 'node_name', 'sim_time'])
            
            # Save to CSV
            df.to_csv(output_file, index=False)
            print(f"   📊 {category.upper()}: {len(data_list):,} points → {output_file.name}")
        
        return self.output_dir

    def cleanup_intermediate_files(self):
        """Clean up intermediate and partial files after final CSV output"""
        print(f"\n🧹 Cleaning up intermediate files...")
        
        cleanup_patterns = [
            "*partial*",
            "*temp*", 
            "*intermediate*",
            "*.tmp"
        ]
        
        files_removed = 0
        for pattern in cleanup_patterns:
            for file_path in self.output_dir.glob(pattern):
                try:
                    file_path.unlink()
                    files_removed += 1
                    print(f"   🗑️  Removed: {file_path.name}")
                except Exception as e:
                    print(f"   ❌ Could not remove {file_path.name}: {e}")
        
        print(f"   ✅ Cleanup completed: {files_removed} intermediate files removed")

        # Create summary
        summary_file = self.output_dir / f"extraction_summary_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(summary_file, 'w') as f:
            f.write("OPTIMIZED TSN METRICS EXTRACTION SUMMARY\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Extraction Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Processing Time: {time.time() - self.start_time:.1f} seconds\n")
            f.write(f"Source Directory: {self.results_dir}\n")
            f.write(f"Output Directory: {self.output_dir}\n\n")
            f.write(f"Extraction completed successfully with memory optimization.\n")
        
        print(f"   📋 Summary: {summary_file.name}")

def main():
    parser = argparse.ArgumentParser(description='Optimized TSN metrics extraction from OMNeT++ .vec files')
    parser.add_argument('--input', '-i', default='simulations/results',
                        help='Input directory (default: simulations/results)')
    parser.add_argument('--output', '-o', default=None,
                        help='Output directory (default: <input>/CSVextractions)')
    parser.add_argument('--processes', '-p', type=int, default=None,
                        help='Number of parallel processes (default: auto)')
    
    args = parser.parse_args()
    
    extractor = OptimizedTSNExtractor(args.input, args.output)
    
    try:
        extractor.run_parallel_extraction()
        print(f"\n✅ SUCCESS: All metrics extracted!")
        
    except KeyboardInterrupt:
        print(f"\n⚠️  Extraction interrupted by user")
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main() 