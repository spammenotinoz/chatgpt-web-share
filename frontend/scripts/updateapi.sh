wget http://127.0.0.1:8000/openapi.json -O src/types/json/openapi.json;
npx openapi-typescript src/types/json/openapi.json --output src/types/openapi.ts;

cd ../backend;
python manage.py get_config_schema > ../frontend/src/types/json/config_schema.json;
python manage.py get_credentials_schema > ../frontend/src/types/json/credentials_schema.json;
python manage.py get_model_definitions > ../frontend/src/types/json/model_definitions.json;
echo "Updated API schemas."