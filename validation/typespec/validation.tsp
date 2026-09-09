namespace Cliptown.Validation;

model RequestMeta {
  @minLength(1) @maxLength(128) requestId: string;
  @minLength(1) @maxLength(128) traceId: string;
  @minLength(2) @maxLength(64) locale?: string;
}

model PageQuery {
  @minValue(1) @maxValue(100) limit: uint16 = 50;
  @minLength(1) @maxLength(512) cursor?: string;
}

model ProblemDetails {
  @minLength(1) @maxLength(512) type: string;
  @minLength(1) @maxLength(256) title: string;
  @minValue(400) @maxValue(599) status: uint16;
  @maxLength(4096) detail?: string;
  @minLength(1) @maxLength(128) requestId: string;
}

// A named union is a first-class contract declaration. Keep it independent
// from the authored JSON Schema while allowing TJSV to compare declaration
// inventory and generated union semantics without special ignore policy.
union PublicValidationContract {
  requestMeta: RequestMeta,
  pageQuery: PageQuery,
  problemDetails: ProblemDetails,
}
