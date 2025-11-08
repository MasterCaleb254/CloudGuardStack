#!/usr/bin/env python3
"""
Multi-cloud log collector for CloudGuardStack
Collects logs from AWS CloudTrail, Azure Activity Logs, and GCP Audit Logs
"""

import json
import socket
import time
from datetime import datetime, timedelta
import boto3
from google.cloud import logging as gcp_logging
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient

class MultiCloudLogCollector:
    def __init__(self, siem_host='localhost', siem_port=5000):
        self.siem_host = siem_host
        self.siem_port = siem_port
        self.setup_clients()
    
    def setup_clients(self):
        """Initialize cloud provider clients"""
        try:
            # AWS clients
            self.cloudtrail = boto3.client('cloudtrail')
            self.cloudwatch = boto3.client('logs')
            
            # Azure clients
            self.azure_credential = DefaultAzureCredential()
            self.subscription_id = self.get_azure_subscription_id()
            self.monitor_client = MonitorManagementClient(
                self.azure_credential, 
                self.subscription_id
            )
            
            # GCP client
            self.gcp_logging_client = gcp_logging.Client()
            
            print("✅ Cloud clients initialized successfully")
            
        except Exception as e:
            print(f"❌ Error initializing cloud clients: {e}")
            raise
    
    def get_azure_subscription_id(self):
        """Get Azure subscription ID"""
        # This would typically come from environment variables or config
        import os
        return os.getenv('AZURE_SUBSCRIPTION_ID', 'demo-subscription-id')
    
    def send_to_siem(self, log_data):
        """Send log data to SIEM"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.siem_host, self.siem_port))
                sock.sendall((json.dumps(log_data) + '\n').encode())
            return True
        except Exception as e:
            print(f"❌ Error sending to SIEM: {e}")
            return False
    
    def collect_aws_cloudtrail_logs(self, hours_back=1):
        """Collect AWS CloudTrail logs"""
        print("🔍 Collecting AWS CloudTrail logs...")
        
        try:
            # Lookup events from last hour
            start_time = datetime.utcnow() - timedelta(hours=hours_back)
            
            response = self.cloudtrail.lookup_events(
                StartTime=start_time,
                MaxResults=50  # Limit for demo
            )
            
            events_collected = 0
            for event in response.get('Events', []):
                log_entry = {
                    'cloud_provider': 'aws',
                    'event_type': 'cloudtrail',
                    'event_time': event.get('EventTime').isoformat(),
                    'event_name': event.get('EventName'),
                    'username': event.get('Username'),
                    'source_ip': event.get('SourceIPAddress'),
                    'raw_event': event
                }
                
                if self.send_to_siem(log_entry):
                    events_collected += 1
            
            print(f"✅ Collected {events_collected} AWS CloudTrail events")
            return events_collected
            
        except Exception as e:
            print(f"❌ Error collecting AWS logs: {e}")
            return 0
    
    def collect_azure_activity_logs(self, hours_back=1):
        """Collect Azure Activity logs"""
        print("🔍 Collecting Azure Activity logs...")
        
        try:
            # This is a simplified version - real implementation would use proper filtering
            start_time = (datetime.utcnow() - timedelta(hours=hours_back)).strftime('%Y-%m-%dT%H:%M:%S')
            
            # Mock data for demo - real implementation would use Azure SDK
            mock_events = [
                {
                    'cloud_provider': 'azure',
                    'event_type': 'activity',
                    'event_time': datetime.utcnow().isoformat(),
                    'operation_name': 'Microsoft.Compute/virtualMachines/write',
                    'caller': 'admin@example.com',
                    'resource_group': 'rg-cloudguardstack',
                    'raw_event': {'category': 'Administrative'}
                }
            ]
            
            events_collected = 0
            for event in mock_events:
                if self.send_to_siem(event):
                    events_collected += 1
            
            print(f"✅ Collected {events_collected} Azure Activity events")
            return events_collected
            
        except Exception as e:
            print(f"❌ Error collecting Azure logs: {e}")
            return 0
    
    def collect_gcp_audit_logs(self, hours_back=1):
        """Collect GCP Audit logs"""
        print("🔍 Collecting GCP Audit logs...")
        
        try:
            # Filter for recent logs
            filter_str = f'timestamp >= "{hours_back}h"'
            
            entries = self.gcp_logging_client.list_entries(
                filter_=filter_str,
                page_size=50
            )
            
            events_collected = 0
            for entry in entries:
                log_entry = {
                    'cloud_provider': 'gcp',
                    'event_type': 'audit',
                    'event_time': entry.timestamp.isoformat(),
                    'log_name': entry.log_name,
                    'severity': entry.severity,
                    'raw_event': {
                        'resource': dict(entry.resource) if entry.resource else {},
                        'labels': dict(entry.labels) if entry.labels else {}
                    }
                }
                
                if self.send_to_siem(log_entry):
                    events_collected += 1
            
            print(f"✅ Collected {events_collected} GCP Audit events")
            return events_collected
            
        except Exception as e:
            print(f"❌ Error collecting GCP logs: {e}")
            return 0
    
    def run_collection(self):
        """Run complete log collection from all clouds"""
        print("🚀 Starting multi-cloud log collection...")
        
        total_events = 0
        total_events += self.collect_aws_cloudtrail_logs()
        total_events += self.collect_azure_activity_logs()
        total_events += self.collect_gcp_audit_logs()
        
        print(f"🎉 Log collection complete! Total events: {total_events}")
        return total_events

if __name__ == "__main__":
    collector = MultiCloudLogCollector()
    collector.run_collection()