# Prevent Sleep/Suspend/Hibernate (Clamshell) 
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target

# List/Modify Bootorder
sudo efibootmgr
sudo efibootmgr -o <first>,<second>
