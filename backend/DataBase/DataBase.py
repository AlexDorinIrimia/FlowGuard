from .config import SUPABASE_URL, SUPABASE_KEY
from supabase import create_client, Client

class Database:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            # Creează instanța unică
            cls._instance = super(Database, cls).__new__(cls)

            # Ia datele de conectare din environment variables (bun pentru securitate)
            url = SUPABASE_URL
            key = SUPABASE_KEY

            if not url or not key:
                raise ValueError("SUPABASE_URL și SUPABASE_KEY trebuie setate în variabilele de mediu.")

            cls._instance.client: Client = create_client(url, key)

        return cls._instance

    def get_client(self) -> Client:
        return self.client
