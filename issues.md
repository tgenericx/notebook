# 🐛 Bug: Invalid/Fragile Provider Factories in forRootAsync (Google Strategy + Guard)

Google-based auth flow unreliable, especially in dynamic config environments where values come from ConfigModule, environment variables, or external services.
