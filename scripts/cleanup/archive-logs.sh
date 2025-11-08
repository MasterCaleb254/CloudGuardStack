#!/bin/bash
set -e

echo "📦 Archiving CloudGuardStack Logs"
echo "================================="

# Configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ARCHIVE_NAME="cloudguardstack-logs-$TIMESTAMP"
ARCHIVE_DIR="logs/archive"
BACKUP_DIR="$ARCHIVE_DIR/$ARCHIVE_NAME"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create archive directory
mkdir -p "$BACKUP_DIR"

echo ""
echo "🔍 Scanning for log files..."

# Find and archive various log files
log_sources=(
    "terraform/*.log"
    "terraform/**/*.log"
    "scanners/*.log"
    "scanners/**/*.log"
    "logs/*.log"
    "*.log"
    "cloudguardstack-*.log"
)

# Collect log files
log_files=()
for pattern in "${log_sources[@]}"; do
    while IFS= read -r -d $'\0' file; do
        if [ -f "$file" ]; then
            log_files+=("$file")
        fi
    done < <(find . -name "*.log" -type f -print0 2>/dev/null)
done

# Remove duplicates
log_files=($(printf "%s\n" "${log_files[@]}" | sort -u))

echo ""
echo "📁 Found ${#log_files[@]} log files to archive:"

if [ ${#log_files[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠️  No log files found to archive${NC}"
    exit 0
fi

# Copy log files to archive directory
for file in "${log_files[@]}"; do
    if [ -f "$file" ]; then
        # Create directory structure in archive
        relative_path="${file#./}"
        archive_path="$BACKUP_DIR/$relative_path"
        mkdir -p "$(dirname "$archive_path")"
        
        cp "$file" "$archive_path"
        file_size=$(du -h "$file" | cut -f1)
        echo -e "${GREEN}✅ Archived: $file ($file_size)${NC}"
    fi
done

echo ""
echo "📊 Creating compressed archive..."

# Create tar archive
cd "$ARCHIVE_DIR"
tar -czf "$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME"

# Calculate archive size
archive_size=$(du -h "$ARCHIVE_NAME.tar.gz" | cut -f1)

echo ""
echo "📦 Archive Information:"
echo -e "   📁 Name: ${BLUE}$ARCHIVE_NAME.tar.gz${NC}"
echo -e "   💾 Size: ${BLUE}$archive_size${NC}"
echo -e "   📍 Location: ${BLUE}$ARCHIVE_DIR/${NC}"
echo -e "   📄 Files: ${BLUE}${#log_files[@]}${NC}"

# Create archive manifest
manifest_file="$BACKUP_DIR/archive-manifest.txt"
echo "CloudGuardStack Log Archive - $TIMESTAMP" > "$manifest_file"
echo "==========================================" >> "$manifest_file"
echo "Archive: $ARCHIVE_NAME.tar.gz" >> "$manifest_file"
echo "Created: $(date)" >> "$manifest_file"
echo "Size: $archive_size" >> "$manifest_file"
echo "" >> "$manifest_file"
echo "Files Archived:" >> "$manifest_file"
echo "--------------" >> "$manifest_file"

for file in "${log_files[@]}"; do
    if [ -f "$file" ]; then
        file_size=$(du -h "$file" | cut -f1)
        echo "- $file ($file_size)" >> "$manifest_file"
    fi
done

echo ""
echo "🧹 Cleaning up temporary files..."
# Remove the uncompressed backup directory
rm -rf "$BACKUP_DIR"

echo ""
echo "📋 Archive Contents Summary:"
cat "$ARCHIVE_DIR/$ARCHIVE_NAME.tar.gz.manifest" 2>/dev/null || echo "No manifest generated"

echo ""
echo "💡 Optional: Upload to cloud storage"
echo "   AWS: aws s3 cp $ARCHIVE_DIR/$ARCHIVE_NAME.tar.gz s3://your-bucket/logs/"
echo "   Azure: az storage blob upload --file $ARCHIVE_DIR/$ARCHIVE_NAME.tar.gz --container-name logs"
echo "   GCP: gsutil cp $ARCHIVE_DIR/$ARCHIVE_NAME.tar.gz gs://your-bucket/logs/"

echo ""
echo "🔄 Rotating old archives (keeping last 10)..."
# Keep only the 10 most recent archives
cd "$ARCHIVE_DIR"
ls -t *.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm

echo ""
echo -e "${GREEN}✅ Log archive completed successfully!${NC}"
echo "📊 Summary:"
echo "   - Archived ${#log_files[@]} log files"
echo "   - Archive size: $archive_size"
echo "   - Location: $ARCHIVE_DIR/$ARCHIVE_NAME.tar.gz"

# Generate checksum for verification
cd "$ARCHIVE_DIR"
sha256sum "$ARCHIVE_NAME.tar.gz" > "$ARCHIVE_NAME.tar.gz.sha256"
echo "   - Checksum: $(cat "$ARCHIVE_NAME.tar.gz.sha256")"

echo ""
echo "🎯 Next steps:"
echo "   - Review archive contents"
echo "   - Upload to cloud storage for long-term retention"
echo "   - Delete local archive if no longer needed"

echo ""
echo "📦 Archive process completed at: $(date)"