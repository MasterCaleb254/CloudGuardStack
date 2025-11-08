#!/bin/bash
set -e

echo "📊 Starting CloudWatch to SIEM log ingestion..."

# Configuration
LOG_GROUP="/cloudguardstack/security"
SIEM_ENDPOINT="http://localhost:5000"
START_TIME="-1h"  # Last 1 hour

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔍 Fetching logs from CloudWatch...${NC}"

# Get log streams from the log group
LOG_STREAMS=$(aws logs describe-log-streams \
  --log-group-name "$LOG_GROUP" \
  --order-by LastEventTime \
  --descending \
  --query 'logStreams[0].logStreamName' \
  --output text)

if [ -z "$LOG_STREAMS" ] || [ "$LOG_STREAMS" = "None" ]; then
    echo "⚠️  No log streams found in $LOG_GROUP"
    exit 0
fi

echo -e "${GREEN}📋 Found log stream: $LOG_STREAMS${NC}"

# Fetch log events
aws logs get-log-events \
  --log-group-name "$LOG_GROUP" \
  --log-stream-name "$LOG_STREAMS" \
  --start-time $(date -d "$START_TIME" +%s)000 \
  --query 'events[*].message' \
  --output text | while read -r line; do
    if [ -n "$line" ]; then
        echo "📨 Sending log to SIEM: $line"
        echo "$line" | nc -q 1 localhost 5000
    fi
done

echo -e "${GREEN}✅ Log ingestion completed!${NC}"
echo "🌐 Check Kibana at: http://localhost:5601"