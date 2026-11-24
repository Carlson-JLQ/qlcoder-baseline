import ...
private class ArchiveEntryNameSource extends DataFlow::Node {
  ArchiveEntryNameSource() {
    exists(MethodCall call |
      call.getMethod() instanceof ArchiveEntryNameMethod and
      this.asExpr() = call
    )
  }
}
private class FileCreationSink extends DataFlow::Node {
  FileCreationSink() { sinkNode(this, "path-injection") }
}

module ZipSlipConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ArchiveEntryNameSource }
  predicate isSink(DataFlow::Node sink) { sink instanceof FileCreationSink }
  predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof PathInjectionSanitizer
  }
}
module ZipSlipFlow = TaintTracking::Global<ZipSlipConfig>;
import ZipSlipFlow::PathGraph
from ZipSlipFlow::PathNode source, ZipSlipFlow::PathNode sink
where ZipSlipFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsanitized archive entry, which may contain '..', is used in a $@.", sink.getNode(),
  "file system operation"
