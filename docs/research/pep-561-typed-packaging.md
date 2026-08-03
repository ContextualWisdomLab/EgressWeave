# PEP 561 typed-package distribution

EgressWeave publishes inline type annotations as part of its supported Python
API. Source annotations alone are not sufficient for downstream type checkers:
the installed package must opt in to typed-package discovery with a `py.typed`
marker.

PEP 561 and the current Python typing specification require maintainers that
ship inline type information to place a `py.typed` marker inside the package.
Type checkers use that marker during import resolution before consuming the
installed `.py` annotations. Without it, editors and CI type checkers may treat
the distribution as untyped even though its source is annotated and its package
metadata declares `Typing :: Typed`.

EgressWeave therefore ships `src/egressweave/py.typed` and protects its presence
with a release-metadata regression test. The marker applies recursively to the
package and contains no runtime behavior.

## Primary references

- [PEP 561: Distributing and Packaging Type Information](https://peps.python.org/pep-0561/)
- [Python typing specification: Distributing type information](https://typing.python.org/en/latest/spec/distributing.html)
