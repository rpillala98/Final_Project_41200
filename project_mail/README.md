gcloud functions deploy newproject \
    --runtime nodejs18 \
    --trigger-topic vulnerability_report \
    --entry-point Main \
    --no-gen2
