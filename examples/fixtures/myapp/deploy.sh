#!/bin/bash
# myapp deployment script
# See README.md → "Deployment Setup" before first run

set -e

echo "Checking prerequisites..."

# Verify SSH key is registered (required)
if [ ! -f ~/.deploy-myapp-registered ]; then
  echo "ERROR: SSH key not registered with deployment server."
  echo "Run Step 3 from README.md first, then retry."
  exit 1
fi

echo "Deploying to $DEPLOY_SERVER..."
rsync -avz --exclude=node_modules . deploy@$DEPLOY_SERVER:/var/www/myapp
ssh deploy@$DEPLOY_SERVER "cd /var/www/myapp && npm install --production && pm2 restart myapp"
echo "Deploy complete!"
