#!/bin/sh
#replace the email below with the email associated with your
#github account
ssh-keygen -t ed25519 -C "ebenezer@olatuyi.com"
echo "Now adding to ssh agent"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

echo "Printing key for copying"

echo "Copy the line below into the area named Secret*"
cat ~/.ssh/id_ed25519
