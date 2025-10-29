REGION="europe-west1"
PROJECT_ID="..."
# Need to be exported for sudo to work
export IMAGE="gcr.io/$PROJECT_ID/mcp-domain-availability:latest"

sudo docker buildx build --platform linux/amd64 -t $IMAGE --push .
sudo docker push $IMAGE

gcloud run deploy mcp-domain-availability \
    --image $IMAGE \
    --region $REGION \
    --platform managed \
    --allow-unauthenticated \
    --port 8080 \
    --project $PROJECT_ID