from typing import Any

# the function provided by the application, e.g. for IDA it should be an idaapi.func_t object,
# but this is not present in test env
NativeFunction = Any  # type: ignore
