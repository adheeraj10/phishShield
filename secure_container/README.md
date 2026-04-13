+ commands to run:

```bash
sudo docker build -t secur-container .

```

```bash
sudo docker run --read-only --name secure-container0 -v "$(pwd)":/app --network host secure-container

```

==network parameter is needed to connect to redis==
