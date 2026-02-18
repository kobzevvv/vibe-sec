#!/bin/bash
# Deployment script — see README.md before first run

if [ ! -f ~/.deploy-myapp-registered ]; then
  echo "ERROR: SSH key not registered. Run Step 3 from README.md first."
  exit 1
fi

echo "Deploying..."
rsync -avz . deploy@deploy.myapp.io:/var/www/myapp
