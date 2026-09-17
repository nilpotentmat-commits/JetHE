#include <cstdint>

// Fixed public dense field map. No HE, sampling or secret-key operation.
extern "C" int sa_matrix(const uint16_t* input, uint16_t* output,
                         const uint16_t* matrix, const uint16_t* logs,
                         const uint16_t* exps, unsigned rows, unsigned cols,
                         unsigned jobs) {
  if (!input || !output || !matrix || !logs || !exps || !rows || !cols ||
      rows > 256 || cols > 256 || jobs > 16) return 1;
  for (unsigned lane = 0; lane < jobs; ++lane)
    for (unsigned row = 0; row < rows; ++row) {
      uint16_t value = 0;
      for (unsigned col = 0; col < cols; ++col) {
        const auto a = input[lane*cols+col], b = matrix[row*cols+col];
        if (a && b) value ^= exps[unsigned(logs[a])+unsigned(logs[b])];
      }
      output[lane*rows+row] = value;
    }
  return 0;
}
