class Errors extends Error {
  statusCode: number;
  productionError: string | null;

  constructor(errorMessage: string, statusCode?: number);
  constructor(error: Error, statusCode?: number, productionError?: string | null)
  
  constructor(
    errorOrMessage: Error | string,
    statusCode: number = 500,
    productionError: string | null = null
  ) {
    if (typeof errorOrMessage === "string") {
      super(errorOrMessage);
      this.productionError = errorOrMessage;
    } else {
      super(JSON.stringify({ message: errorOrMessage.message, details: errorOrMessage }));
      this.productionError = productionError;
    }
    this.statusCode = statusCode;
  }

  // Override the toJSON method to provide custom error serialization
  toJSON() {
    return {
      message: this.message,
      stack: this.stack,
      statusCode: this.statusCode,
    };
  }

  // Method to throw the error in a structured response
  static throwError(error: Errors) {
    error = error instanceof Errors ? error : new Errors(error);
    
    if (process.env.IS_DEVELOP === 'true') {
      return new Response(JSON.stringify(error),
        { status: error.statusCode });
    }

    return new Response(
      JSON.stringify(
        error.productionError ?? 'Something went wrong. Please try again after some time.'),
      { status: error.statusCode });
  }

  // Method to throw the error in a structured response stream
  static throwErrorStream(error: Errors) {
    error = error instanceof Errors ? error : new Errors(error);
    
    if (process.env.IS_DEVELOP === 'true') {
      return (JSON.stringify(error));
    }

    return (
      JSON.stringify(
        error.productionError ?? 'Something went wrong. Please try again after some time.'));
  }
}

export default Errors;
