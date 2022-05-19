int inv(int a) {
  int b = __GADGET_compute(1000/a);
  __GADGET_check(b * a == 1000);
  return b;
}
