#define BUILDING_NODE_EXTENSION
#include <node.h>
#include "csr.h"

using namespace v8;

void init(Handle<Object> target) {
  CSR::Initialize(target);
}

NODE_MODULE(binding, init)