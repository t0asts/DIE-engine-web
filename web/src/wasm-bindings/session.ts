
export interface SessionHandle {
  hot(exportName: string, args: unknown[]): any;
  invoke(methodId: number, args: unknown[]): any;
}
