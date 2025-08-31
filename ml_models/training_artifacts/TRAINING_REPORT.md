# Training Report

## Data inputs

- Files used: 40 (see training_artifacts/inputs_used.json)

## Labels

- Counts: {'normal': 11000, 'timing_attack': 4000, 'dos_attack': 3000, 'spoofing_attack': 2000}

## Features

- feature_order (15): ['throughput_bps_tx', 'packets_sent', 'packets_received', 'packets_dropped', 'drop_rate', 'queue_length_max', 'ptp_offset_mean', 'ptp_offset_max', 'rate_ratio_mean', 'peer_delay_mean', 'e2e_delay_avg', 'e2e_delay_max', 'e2e_delay_std', 'has_ptp', 'has_e2e']

## Split

- By file; train/test lists saved next to this report

## Metrics

```

              precision    recall  f1-score   support

           0     0.8856    0.7491    0.8117      3400
           1     0.7270    0.8735    0.7935      2600

    accuracy                         0.8030      6000
   macro avg     0.8063    0.8113    0.8026      6000
weighted avg     0.8169    0.8030    0.8038      6000


```

- Confusion matrix: [[2547, 853], [329, 2271]]

- ROC AUC: 0.8549994343891403

- PR AUC: 0.7484785369751129