#!/bin/bash

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Dieses Script muss mit root-Rechten ausgeführt werden."
    echo "Bitte mit sudo ausführen."
    exit 1
fi

# Definiere Zielpfad und Dateinamen
POLICY_DIR="/etc/opt/chrome/policies/enrollment"
TOKEN_FILE="CloudManagementEnrollmentToken"
MANDATORY_FILE="CloudManagementEnrollmentMandatory"

# Erstelle Verzeichnisse falls sie nicht existieren
mkdir -p "$POLICY_DIR"

# Schreibe Token in Datei
echo "98a4b66a-b679-4164-9043-ee10f9fa870a" > "$POLICY_DIR/$TOKEN_FILE"
echo "Mandatory" > "$POLICY_DIR/$MANDATORY_FILE"

# Setze korrekte Berechtigungen
chmod 644 "$POLICY_DIR/$TOKEN_FILE"
chmod 644 "$POLICY_DIR/$MANDATORY_FILE"

# Überprüfe ob alles geklappt hat
if [ $? -eq 0 ]; then
    echo "Chrome enrollment token file wurde erfolgreich erstellt"
else
    echo "Fehler beim Erstellen des Tokens"
    exit 1
fi
