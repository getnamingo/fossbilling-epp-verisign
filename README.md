# Compatibility

This module supports **all gTLDs** that use the VeriSign platform.

# FOSSBilling Module Installation instructions

## 1. Download and Install FOSSBilling:

Start by downloading the latest version of FOSSBilling from the official website (https://fossbilling.org/). Then follow the instructions below to install the module, or run for automated installation:

```bash
wget https://raw.githubusercontent.com/getnamingo/fossbilling-epp-verisign/main/install_verisign_module.sh -O install_verisign_module.sh && chmod +x install_verisign_module.sh && ./install_verisign_module.sh
```

## 2. Installation and Configuration of Registrar Adapter:

First, download this repository which contains the VeriSign.php file. After successfully downloading the repository, move the VeriSign.php file into the `[FOSSBilling]/library/Registrar/Adapter` directory.

## 3. Addition of Synchronization Script:

There is one additional script in the repository: **VeriSignSync.php**. It needs to be placed in the main `[FOSSBilling]` directory.

## 4. Setting Up the Cron Job:

You need to set up a cron job that runs the sync module twice a day. Open crontab using the command `crontab -e` in your terminal.

Add the following cron job:

`0 0,12 * * * php /var/www/html/VeriSignSync.php`

This command schedules the synchronization script to run once every 12 hours (at midnight and noon).

## 5. Activate the Domain Registrar Module:

Within FOSSBilling, go to **System -> Domain Registration -> New Domain Registrar** and activate the new domain registrar.

## 6. Registrar Configuration:

Next, head to the "**Registrars**" tab. Here, you'll need to enter your specific configuration details, including the path to your SSL certificate and key.

## 7. Adding a New TLD:

Finally, add a new Top Level Domain (TLD) using your module from the "**New Top Level Domain**" tab. Make sure to configure all necessary details, such as pricing, within this tab.

# Troubleshooting

If you experience problems connecting to your EPP server, follow these steps:

1. Ensure your server's IP (IPv4 and IPv6) is whitelisted by the EPP server.

2. Confirm your client and server support IPv6 if required. If needed, disable IPv6 support in EPP server.

3. Reload the EPP module or restart the web server after any changes.

4. Ensure certificates have the correct permissions: `chown www-data:www-data cert.pem` and `chown www-data:www-data key.pem`.

5. Verify the EPP module is configured with the chosen registrar prefix.