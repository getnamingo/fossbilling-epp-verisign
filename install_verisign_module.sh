#!/bin/bash

# Ask for FOSSBilling directory
echo "Enter the path to the FOSSBilling directory (default is /var/www):"
read -r fossbilling_path
fossbilling_path=${fossbilling_path:-/var/www}

# Clone the repository to /tmp
git clone https://github.com/getnamingo/fossbilling-epp-verisign /tmp/fossbilling-epp-verisign

# Move the VeriSign.php file
mv /tmp/fossbilling-epp-verisign/VeriSign.php "$fossbilling_path/library/Registrar/Adapter/VeriSign.php"

# Move the VeriSignSync.php file
mv /tmp/fossbilling-epp-verisign/VeriSignSync.php "$fossbilling_path/VeriSignSync.php"

# Add the cron job
(crontab -l 2>/dev/null; echo "0 0,12 * * * php $fossbilling_path/VeriSignSync.php") | crontab -

# Clean up
rm -rf /tmp/fossbilling-epp-verisign

# Final instructions
echo "Installation complete."
echo ""
echo "1. Activate the Domain Registrar Module:"
echo "Within FOSSBilling, go to System -> Domain Registration -> New Domain Registrar and activate the new domain registrar."
echo ""
echo "2. Registrar Configuration:"
echo "Next, head to the 'Registrars' tab. Here, you'll need to enter your specific configuration details, including the path to your SSL certificate and key."
echo ""
echo "3. Adding a New TLD:"
echo "Finally, add a new Top Level Domain (TLD) using your module from the 'New Top Level Domain' tab. Make sure to configure all necessary details, such as pricing, within this tab."