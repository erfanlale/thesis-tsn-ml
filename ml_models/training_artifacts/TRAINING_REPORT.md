# Training Report


## Data inputs


- Files used: 40 (restricted to simulations/results_flat)

- See training_artifacts/inputs_used.json for full list

## Labels


- Label counts: {'normal': 11000, 'timing_attack': 4000, 'dos_attack': 3000, 'spoofing_attack': 2000}

## Features


- feature_order: ['throughput_bps_tx', 'packets_sent', 'packets_received', 'packets_dropped', 'drop_rate', 'queue_length_max', 'ptp_offset_mean', 'ptp_offset_max', 'rate_ratio_mean', 'peer_delay_mean', 'e2e_delay_avg', 'e2e_delay_max', 'e2e_delay_std', 'has_ptp', 'has_e2e']

## Split


- By file; see training_artifacts/train_files.json and test_files.json

## Metrics


```$              precision    recall  f1-score   support

           0     0.9356    0.7091    0.8068      3400
           1     0.7111    0.9362    0.8082      2600

    accuracy                         0.8075      6000
   macro avg     0.8233    0.8226    0.8075      6000
weighted avg     0.8383    0.8075    0.8074      6000
```

- Confusion matrix: [[2411, 989], [166, 2434]]

- ROC AUC: 0.8659953619909502

- PR AUC: 0.7700597526335978