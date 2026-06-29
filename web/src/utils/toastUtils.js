let _counter = 0
export const createToastId = () => `toast_${Date.now()}_${++_counter}`