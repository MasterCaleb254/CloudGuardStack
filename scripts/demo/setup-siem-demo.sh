#!/bin/bash
set -e

echo "🎪 Setting up SIEM Demo Environment"
echo "==================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo -e "${BLUE}1. Starting Elastic Stack...${NC}"
cd siem
docker-compose up -d

echo -e "${BLUE}2. Waiting for services to start...${NC}"
sleep 30

echo -e "${BLUE}3. Checking service status...${NC}"
if curl -s http://localhost:9200 > /dev/null; then
    echo -e "${GREEN}✅ Elasticsearch is running${NC}"
else
    echo "❌ Elasticsearch failed to start"
    exit 1
fi

if curl -s http://localhost:5601 > /dev/null; then
    echo -e "${GREEN}✅ Kibana is running${NC}"
else
    echo "❌ Kibana failed to start"
    exit 1
fi

echo -e "${BLUE}4. Creating demo log data...${NC}"
python3 scripts/log-ingestion/multi-cloud-collector.py

echo -e "${GREEN}🎉 SIEM Demo Setup Complete!${NC}"
echo ""
echo "📊 Access your SIEM dashboard:"
echo "   Kibana: http://localhost:5601"
echo "   Elasticsearch: http://localhost:9200"
echo "   Logstash: localhost:5044 (Beats), localhost:5000 (TCP)"
echo ""
echo "🔧 Useful commands:"
echo "   View logs: docker-compose logs -f"
echo "   Stop SIEM: docker-compose down"
echo "   Reset data: docker-compose down -v"