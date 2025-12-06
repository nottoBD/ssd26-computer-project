# 1. First time
something along the lines, adapt to your OS
```
git clone https://github.com/nottoBD/ssd26-computer-project.git
cd ssd26-computer-project
copy .env.example .env      # Windows
pip install uv && uv --version
cd server
sudo rm -rf .venv           # Linux
uv venv .venv
source .venv/bin/activate   # Bash
uv sync
cd ../client
npm install -g corepack@latest
corepack enable pnpm
corepack prepare pnpm@latest --activate
```

# 2. Start
```
docker compose up --build
```

# 3. Stop everything
```
docker compose down
```

# 4. Full reset 
(database + volumes) after model changes
```
docker compose down -v
```

# 5. Rebuild only backend only 
(after adding Python packages or model changes)
```
docker compose build server
docker compose up server
```

# 6. Rebuild frontend only 
(after adding shadcn components, tailwind, etc.)
```
docker compose build client
docker compose up client
```

# 7. Enter backend container 
(for migrations, superuser, shell…)
```
docker compose exec server bash
```

# Inside the container Django commands
```
uv run python manage.py migrate
uv run python manage.py makemigrations
uv run python manage.py createsuperuser
uv run python manage.py shell
uv run python manage.py test
```

# 8. Add/remove Python packages 
(inside backend container OR on host)
```
uv add django-cors-headers
uv add djangorestframework
uv add fido2
uv add --dev black ruff
uv remove some-package
```

# 9. Frontend packages 
(from client/ folder)
```
cd client
pnpm add zod @tanstack/react-query axios
pnpm add -D @types/node
npx shadcn@latest add dialog sheet toast dropdown-menu avatar badge
```

# 10. Prune everything 
when Docker gets too fat
```
docker system prune -a --volumes
docker builder prune -f
docker volume prune -f
```

# 11. View logs 
for specific service
```
docker compose logs -f server
docker compose logs -f client
docker compose logs -f db
```

# 12. One-liner 
to nuke everything and start fresh
```
docker compose down -v && docker system prune -f --volumes && docker compose up --build
```
