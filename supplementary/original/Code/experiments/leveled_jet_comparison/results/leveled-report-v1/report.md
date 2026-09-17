# Measured leveled-library comparison

Verified 92 cases, 644 retained trials, and 158256 recorded output coefficients.

These reports check recorded integrity and finite-trial decoded correctness. The requested HEStd_128_classic library preset is not an independent security certification. No ExactJet or refresh execution is represented.

Pipeline = encode + encrypt + evaluate + decrypt + decode for each trial; setup and precomputation are excluded and recorded separately. Decode includes output comparison/bookkeeping; precomputation includes fixture/oracle construction and interpolation weights. Balanced circuits run serially and do not measure a CPU-parallel speedup. Ranges are sample min/max, not confidence intervals. Throughput is computed per trial before summarizing. Peak RSS covers the whole process. Byte counts use separate uncompressed library serializations. One warmup is excluded; its outputs are not in the independent checks.

## Bound runs

- Run 1: `leveled-main-v2`; 80 cases; OpenFHE 1.5.1; SHA-256 `4e57d1bab9a9eb946b084c11778213c6816adf2763164121802896d13b03afd1`.
  Manifest: `Code/experiments/leveled_jet_comparison/results/leveled-main-v2/manifest.json`.
  Environment: `{"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": 1, "cpu": "AMD Ryzen 9 9950X 16-Core Processor", "execution_order_seed": 20260905, "logical_processors": 32, "machine": "AMD64", "os": "Windows-11-10.0.26200-SP0", "physical_memory_bytes": 33243181056, "python": "3.14.4 (tags/v3.14.4:23116f9, Apr  7 2026, 14:10:54) [MSC v.1944 64 bit (AMD64)]", "timed_processes_parallel": false}`.
- Run 2: `leveled-capacity-v1`; 4 cases; OpenFHE 1.5.1; SHA-256 `34f7b5b5c527f9e76d8d9d455b87242dbbc3495ab3af1a36f01e44d51c056abb`.
  Manifest: `Code/experiments/leveled_jet_comparison/results/leveled-capacity-v1/manifest.json`.
  Environment: `{"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": 1, "cpu": "AMD Ryzen 9 9950X 16-Core Processor", "execution_order_seed": 20260905, "logical_processors": 32, "machine": "AMD64", "os": "Windows-11-10.0.26200-SP0", "physical_memory_bytes": 33243181056, "python": "3.14.4 (tags/v3.14.4:23116f9, Apr  7 2026, 14:10:54) [MSC v.1944 64 bit (AMD64)]", "timed_processes_parallel": false}`.
- Run 3: `leveled-seed-control-v1`; 8 cases; OpenFHE 1.5.1; SHA-256 `8520b50ed4be5eb900bb4104d9e4dadd109f97c1d5e05f65b59632b25010fc31`.
  Manifest: `Code/experiments/leveled_jet_comparison/results/leveled-seed-control-v1/manifest.json`.
  Environment: `{"OMP_DYNAMIC": "FALSE", "OMP_NUM_THREADS": 1, "cpu": "AMD Ryzen 9 9950X 16-Core Processor", "execution_order_seed": 20260905, "logical_processors": 32, "machine": "AMD64", "os": "Windows-11-10.0.26200-SP0", "physical_memory_bytes": 33243181056, "python": "3.14.4 (tags/v3.14.4:23116f9, Apr  7 2026, 14:10:54) [MSC v.1944 64 bit (AMD64)]", "timed_processes_parallel": false}`.

## Sequential grid, J = 1

Cells are median evaluation / pipeline milliseconds.

| e | d | BGV native | BGV terminal packed | BFV native | BFV terminal packed |
|---:|---:|---:|---:|---:|---:|
| 4 | 1 | 2.766 / 11.018 | 3.117 / 8.971 | 5.048 / 13.242 | 4.852 / 11.012 |
| 4 | 2 | 7.946 / 22.349 | 16.638 / 35.211 | 9.809 / 21.650 | 16.134 / 28.571 |
| 4 | 4 | 22.868 / 55.007 | 49.457 / 90.091 | 29.283 / 55.002 | 76.768 / 124.116 |
| 8 | 1 | 2.808 / 10.933 | 3.064 / 8.871 | 4.925 / 13.131 | 5.076 / 11.542 |
| 8 | 2 | 7.866 / 22.912 | 17.030 / 36.160 | 9.849 / 21.595 | 15.269 / 27.083 |
| 8 | 4 | 22.895 / 55.149 | 49.091 / 90.230 | 28.188 / 53.355 | 76.681 / 124.300 |
| 16 | 1 | 2.896 / 11.306 | 3.461 / 9.940 | 4.926 / 13.060 | 4.814 / 10.979 |
| 16 | 2 | 7.729 / 22.137 | 16.545 / 35.247 | 9.506 / 21.109 | 15.060 / 26.847 |
| 16 | 4 | 22.961 / 54.602 | 49.414 / 89.921 | 28.426 / 53.528 | 76.022 / 123.483 |

## Sequential grid, J = 16

Cells are median evaluation / pipeline milliseconds.

| e | d | BGV native | BGV terminal packed | BFV native | BFV terminal packed |
|---:|---:|---:|---:|---:|---:|
| 4 | 1 | 36.171 / 152.083 | 3.096 / 8.899 | 67.285 / 185.746 | 4.775 / 10.930 |
| 4 | 2 | 104.195 / 309.715 | 16.916 / 35.663 | 134.795 / 313.156 | 15.047 / 26.983 |
| 4 | 4 | 342.761 / 827.168 | 48.897 / 88.592 | 415.630 / 821.313 | 75.884 / 123.838 |
| 8 | 1 | 35.817 / 152.023 | 3.081 / 8.894 | 67.601 / 187.265 | 5.322 / 12.006 |
| 8 | 2 | 105.137 / 312.364 | 16.803 / 35.799 | 134.857 / 312.223 | 15.087 / 27.225 |
| 8 | 4 | 344.721 / 827.796 | 49.011 / 89.232 | 415.751 / 820.090 | 76.867 / 124.812 |
| 16 | 1 | 36.001 / 151.269 | 3.146 / 9.180 | 67.650 / 186.112 | 4.871 / 11.121 |
| 16 | 2 | 105.469 / 311.589 | 16.917 / 36.207 | 133.814 / 308.971 | 15.220 / 27.250 |
| 16 | 4 | 341.273 / 852.467 | 49.130 / 89.850 | 415.020 / 821.940 | 76.382 / 124.322 |

## Every retained case

Timing cells show median [min, max] milliseconds. The CSV contains every phase, resource, modulus and throughput field at full serialized precision.

| Run | Scheme/layout | Schedule | e | d | J | Seed | Evaluation | Pipeline | Pipeline jobs/s |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1 | BFV native | sequential | 4 | 1 | 1 | 11 | 5.048 [4.784, 5.322] | 13.242 [12.685, 14.115] | 75.516 |
| 1 | BFV terminal packed | sequential | 4 | 1 | 1 | 11 | 4.852 [4.757, 4.989] | 11.012 [10.888, 11.369] | 90.810 |
| 1 | BGV native | sequential | 4 | 1 | 1 | 11 | 2.766 [2.675, 2.868] | 11.018 [10.892, 11.408] | 90.758 |
| 1 | BGV terminal packed | sequential | 4 | 1 | 1 | 11 | 3.117 [3.051, 3.300] | 8.971 [8.782, 9.267] | 111.475 |
| 1 | BFV native | sequential | 4 | 1 | 16 | 11 | 67.285 [67.003, 67.558] | 185.746 [185.189, 196.399] | 86.139 |
| 1 | BFV terminal packed | sequential | 4 | 1 | 16 | 11 | 4.775 [4.723, 5.074] | 10.930 [10.814, 11.252] | 1463.901 |
| 1 | BGV native | sequential | 4 | 1 | 16 | 11 | 36.171 [36.089, 36.574] | 152.083 [151.915, 153.384] | 105.205 |
| 1 | BGV terminal packed | sequential | 4 | 1 | 16 | 11 | 3.096 [2.998, 3.417] | 8.899 [8.671, 9.352] | 1797.854 |
| 1 | BFV native | sequential | 4 | 2 | 1 | 11 | 9.809 [9.623, 10.194] | 21.650 [21.211, 22.135] | 46.190 |
| 1 | BFV terminal packed | sequential | 4 | 2 | 1 | 11 | 16.134 [15.566, 16.754] | 28.571 [27.549, 29.347] | 35.001 |
| 1 | BGV native | sequential | 4 | 2 | 1 | 11 | 7.946 [7.492, 8.402] | 22.349 [21.976, 23.386] | 44.745 |
| 1 | BGV terminal packed | sequential | 4 | 2 | 1 | 11 | 16.638 [16.512, 17.041] | 35.211 [34.975, 36.034] | 28.401 |
| 1 | BFV native | sequential | 4 | 2 | 16 | 11 | 134.795 [134.495, 137.323] | 313.156 [310.188, 315.522] | 51.093 |
| 1 | BFV terminal packed | sequential | 4 | 2 | 16 | 11 | 15.047 [14.643, 15.456] | 26.983 [26.626, 27.263] | 592.959 |
| 1 | BGV native | sequential | 4 | 2 | 16 | 11 | 104.195 [103.902, 105.233] | 309.715 [307.604, 311.161] | 51.660 |
| 1 | BGV terminal packed | sequential | 4 | 2 | 16 | 11 | 16.916 [16.436, 17.045] | 35.663 [35.257, 36.132] | 448.651 |
| 1 | BFV native | sequential | 4 | 4 | 1 | 11 | 29.283 [28.388, 29.983] | 55.002 [53.775, 56.086] | 18.181 |
| 1 | BFV terminal packed | sequential | 4 | 4 | 1 | 11 | 76.768 [75.138, 77.469] | 124.116 [123.016, 125.936] | 8.057 |
| 1 | BGV native | sequential | 4 | 4 | 1 | 11 | 22.868 [22.368, 23.576] | 55.007 [54.027, 56.271] | 18.180 |
| 1 | BGV terminal packed | sequential | 4 | 4 | 1 | 11 | 49.457 [48.722, 49.993] | 90.091 [88.983, 92.692] | 11.100 |
| 1 | BFV native | sequential | 4 | 4 | 16 | 11 | 415.630 [390.616, 428.822] | 821.313 [771.611, 835.142] | 19.481 |
| 1 | BFV terminal packed | sequential | 4 | 4 | 16 | 11 | 75.884 [75.372, 77.475] | 123.838 [122.702, 125.119] | 129.201 |
| 1 | BGV native | sequential | 4 | 4 | 16 | 11 | 342.761 [318.769, 347.049] | 827.168 [770.221, 842.666] | 19.343 |
| 1 | BGV terminal packed | sequential | 4 | 4 | 16 | 11 | 48.897 [47.714, 49.415] | 88.592 [87.911, 90.091] | 180.602 |
| 1 | BFV native | sequential | 8 | 1 | 1 | 11 | 4.925 [4.870, 5.280] | 13.131 [12.980, 13.637] | 76.155 |
| 1 | BFV terminal packed | sequential | 8 | 1 | 1 | 11 | 5.076 [4.862, 5.257] | 11.542 [11.209, 11.839] | 86.638 |
| 1 | BGV native | sequential | 8 | 1 | 1 | 11 | 2.808 [2.627, 3.274] | 10.933 [10.692, 11.287] | 91.466 |
| 1 | BGV terminal packed | sequential | 8 | 1 | 1 | 11 | 3.064 [2.982, 3.261] | 8.871 [8.518, 9.211] | 112.729 |
| 1 | BFV native | sequential | 8 | 1 | 16 | 11 | 67.601 [67.486, 68.444] | 187.265 [186.247, 187.880] | 85.440 |
| 1 | BFV terminal packed | sequential | 8 | 1 | 16 | 11 | 5.322 [4.986, 5.623] | 12.006 [11.712, 12.625] | 1332.645 |
| 1 | BGV native | sequential | 8 | 1 | 16 | 11 | 35.817 [35.712, 36.045] | 152.023 [151.005, 152.571] | 105.248 |
| 1 | BGV terminal packed | sequential | 8 | 1 | 16 | 11 | 3.081 [2.960, 3.185] | 8.894 [8.623, 9.080] | 1799.026 |
| 1 | BFV native | sequential | 8 | 2 | 1 | 11 | 9.849 [9.683, 9.995] | 21.595 [21.382, 21.819] | 46.308 |
| 1 | BFV terminal packed | sequential | 8 | 2 | 1 | 11 | 15.269 [14.841, 15.601] | 27.083 [26.939, 27.679] | 36.924 |
| 1 | BGV native | sequential | 8 | 2 | 1 | 11 | 7.866 [7.588, 8.250] | 22.912 [22.493, 23.025] | 43.646 |
| 1 | BGV terminal packed | sequential | 8 | 2 | 1 | 11 | 17.030 [16.409, 17.381] | 36.160 [35.157, 36.702] | 27.655 |
| 1 | BFV native | sequential | 8 | 2 | 16 | 11 | 134.857 [133.381, 135.121] | 312.223 [309.750, 313.151] | 51.245 |
| 1 | BFV terminal packed | sequential | 8 | 2 | 16 | 11 | 15.087 [14.788, 15.510] | 27.225 [26.959, 27.845] | 587.699 |
| 1 | BGV native | sequential | 8 | 2 | 16 | 11 | 105.137 [104.639, 105.641] | 312.364 [310.461, 313.056] | 51.222 |
| 1 | BGV terminal packed | sequential | 8 | 2 | 16 | 11 | 16.803 [16.422, 17.120] | 35.799 [35.326, 36.810] | 446.945 |
| 1 | BFV native | sequential | 8 | 4 | 1 | 11 | 28.188 [27.977, 28.719] | 53.355 [52.915, 54.051] | 18.742 |
| 1 | BFV terminal packed | sequential | 8 | 4 | 1 | 11 | 76.681 [76.260, 78.134] | 124.300 [124.022, 127.972] | 8.045 |
| 1 | BGV native | sequential | 8 | 4 | 1 | 11 | 22.895 [22.634, 23.395] | 55.149 [54.144, 56.080] | 18.133 |
| 1 | BGV terminal packed | sequential | 8 | 4 | 1 | 11 | 49.091 [48.825, 49.364] | 90.230 [88.660, 90.334] | 11.083 |
| 1 | BFV native | sequential | 8 | 4 | 16 | 11 | 415.751 [395.740, 461.348] | 820.090 [776.983, 893.779] | 19.510 |
| 1 | BFV terminal packed | sequential | 8 | 4 | 16 | 11 | 76.867 [76.130, 78.049] | 124.812 [123.691, 126.004] | 128.192 |
| 1 | BGV native | sequential | 8 | 4 | 16 | 11 | 344.721 [320.554, 354.904] | 827.796 [774.986, 886.038] | 19.328 |
| 1 | BGV terminal packed | sequential | 8 | 4 | 16 | 11 | 49.011 [47.822, 49.452] | 89.232 [87.492, 89.910] | 179.308 |
| 1 | BFV native | sequential | 16 | 1 | 1 | 11 | 4.926 [4.844, 5.234] | 13.060 [12.841, 13.887] | 76.568 |
| 1 | BFV terminal packed | sequential | 16 | 1 | 1 | 11 | 4.814 [4.771, 5.118] | 10.979 [10.917, 11.411] | 91.083 |
| 1 | BGV native | sequential | 16 | 1 | 1 | 11 | 2.896 [2.811, 3.130] | 11.306 [11.124, 11.610] | 88.451 |
| 1 | BGV terminal packed | sequential | 16 | 1 | 1 | 11 | 3.461 [3.324, 3.737] | 9.940 [9.539, 10.316] | 100.606 |
| 1 | BFV native | sequential | 16 | 1 | 16 | 11 | 67.650 [67.217, 67.970] | 186.112 [185.602, 186.518] | 85.970 |
| 1 | BFV terminal packed | sequential | 16 | 1 | 16 | 11 | 4.871 [4.798, 4.977] | 11.121 [10.991, 11.538] | 1438.732 |
| 1 | BGV native | sequential | 16 | 1 | 16 | 11 | 36.001 [35.661, 36.467] | 151.269 [150.857, 152.441] | 105.772 |
| 1 | BGV terminal packed | sequential | 16 | 1 | 16 | 11 | 3.146 [3.027, 3.371] | 9.180 [8.848, 9.403] | 1742.900 |
| 1 | BFV native | sequential | 16 | 2 | 1 | 11 | 9.506 [9.409, 9.812] | 21.109 [20.881, 21.326] | 47.373 |
| 1 | BFV terminal packed | sequential | 16 | 2 | 1 | 11 | 15.060 [14.604, 15.307] | 26.847 [26.495, 26.953] | 37.248 |
| 1 | BGV native | sequential | 16 | 2 | 1 | 11 | 7.729 [7.504, 7.995] | 22.137 [21.646, 22.445] | 45.173 |
| 1 | BGV terminal packed | sequential | 16 | 2 | 1 | 11 | 16.545 [16.415, 17.153] | 35.247 [35.053, 36.028] | 28.371 |
| 1 | BFV native | sequential | 16 | 2 | 16 | 11 | 133.814 [132.980, 134.339] | 308.971 [307.275, 309.963] | 51.785 |
| 1 | BFV terminal packed | sequential | 16 | 2 | 16 | 11 | 15.220 [14.934, 15.461] | 27.250 [27.073, 27.745] | 587.149 |
| 1 | BGV native | sequential | 16 | 2 | 16 | 11 | 105.469 [105.017, 106.354] | 311.589 [309.656, 373.207] | 51.350 |
| 1 | BGV terminal packed | sequential | 16 | 2 | 16 | 11 | 16.917 [16.578, 17.341] | 36.207 [35.495, 36.580] | 441.903 |
| 1 | BFV native | balanced | 16 | 4 | 1 | 11 | 30.797 [30.490, 31.021] | 55.820 [55.057, 56.118] | 17.915 |
| 1 | BFV terminal packed | balanced | 16 | 4 | 1 | 11 | 81.722 [80.451, 82.360] | 129.565 [128.064, 129.780] | 7.718 |
| 1 | BGV native | balanced | 16 | 4 | 1 | 11 | 25.421 [24.951, 25.793] | 57.424 [56.476, 58.644] | 17.414 |
| 1 | BGV terminal packed | balanced | 16 | 4 | 1 | 11 | 55.565 [53.354, 56.837] | 96.558 [94.388, 103.617] | 10.356 |
| 1 | BFV native | sequential | 16 | 4 | 1 | 11 | 28.426 [27.980, 29.113] | 53.528 [53.083, 54.303] | 18.682 |
| 1 | BFV terminal packed | sequential | 16 | 4 | 1 | 11 | 76.022 [75.585, 76.498] | 123.483 [122.079, 124.273] | 8.098 |
| 1 | BGV native | sequential | 16 | 4 | 1 | 11 | 22.961 [22.498, 23.501] | 54.602 [54.090, 55.805] | 18.314 |
| 1 | BGV terminal packed | sequential | 16 | 4 | 1 | 11 | 49.414 [49.082, 50.647] | 89.921 [89.222, 92.866] | 11.121 |
| 1 | BFV native | balanced | 16 | 4 | 16 | 11 | 445.057 [421.716, 454.559] | 853.332 [799.623, 876.723] | 18.750 |
| 1 | BFV terminal packed | balanced | 16 | 4 | 16 | 11 | 82.472 [81.740, 84.298] | 130.819 [130.344, 133.616] | 122.306 |
| 1 | BGV native | balanced | 16 | 4 | 16 | 11 | 372.013 [347.103, 394.336] | 894.846 [799.620, 923.175] | 17.880 |
| 1 | BGV terminal packed | balanced | 16 | 4 | 16 | 11 | 54.432 [53.833, 56.466] | 96.287 [94.836, 98.908] | 166.169 |
| 1 | BFV native | sequential | 16 | 4 | 16 | 11 | 415.020 [387.110, 427.343] | 821.940 [766.899, 853.615] | 19.466 |
| 1 | BFV terminal packed | sequential | 16 | 4 | 16 | 11 | 76.382 [75.851, 76.801] | 124.322 [123.793, 124.817] | 128.698 |
| 1 | BGV native | sequential | 16 | 4 | 16 | 11 | 341.273 [326.404, 382.664] | 852.467 [784.841, 924.884] | 18.769 |
| 1 | BGV terminal packed | sequential | 16 | 4 | 16 | 11 | 49.130 [48.575, 49.573] | 89.850 [88.214, 90.882] | 178.075 |
| 2 | BFV native | sequential | 16 | 4 | 215 | 11 | 5641.984 [5479.634, 7222.499] | 11297.516 [10653.351, 13170.521] | 19.031 |
| 2 | BFV terminal packed | sequential | 16 | 4 | 215 | 11 | 76.329 [75.961, 77.312] | 125.944 [125.419, 127.265] | 1707.102 |
| 2 | BGV native | sequential | 16 | 4 | 215 | 11 | 6604.639 [6198.384, 7525.708] | 14245.037 [13220.917, 15288.873] | 15.093 |
| 2 | BGV terminal packed | sequential | 16 | 4 | 215 | 11 | 50.285 [49.668, 51.528] | 94.624 [93.080, 96.481] | 2272.163 |
| 3 | BFV native | balanced | 16 | 4 | 16 | 29 | 444.275 [422.589, 456.831] | 851.037 [807.396, 877.560] | 18.801 |
| 3 | BFV terminal packed | balanced | 16 | 4 | 16 | 29 | 80.975 [79.910, 81.956] | 128.960 [127.520, 129.696] | 124.069 |
| 3 | BGV native | balanced | 16 | 4 | 16 | 29 | 381.012 [342.958, 395.491] | 865.680 [795.865, 889.315] | 18.483 |
| 3 | BGV terminal packed | balanced | 16 | 4 | 16 | 29 | 54.926 [53.515, 55.105] | 96.297 [94.725, 97.347] | 166.152 |
| 3 | BFV native | sequential | 16 | 4 | 16 | 29 | 416.763 [383.292, 443.987] | 830.784 [756.695, 855.794] | 19.259 |
| 3 | BFV terminal packed | sequential | 16 | 4 | 16 | 29 | 75.376 [74.540, 75.655] | 122.478 [121.309, 123.788] | 130.636 |
| 3 | BGV native | sequential | 16 | 4 | 16 | 29 | 340.924 [318.925, 376.767] | 836.171 [766.621, 886.354] | 19.135 |
| 3 | BGV terminal packed | sequential | 16 | 4 | 16 | 29 | 48.437 [48.300, 49.235] | 88.849 [87.522, 89.833] | 180.080 |

## Report source bindings

- `Code/experiments/leveled_jet_comparison/summarize_results.py`: SHA-256 `92f53534d2671417c6ce299c708899278baa3b462e7470a4e0cbe70ba24c7965` (24588 bytes).
- `Code/experiments/leveled_jet_comparison/verify_results.py`: SHA-256 `3ac4ab08683d6dd11a8584d3722108dbceda8f454f4b652c782588d0d61b824f` (20385 bytes).
