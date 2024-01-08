<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sign in - Workshop For Beginners</title>
    <link href="<?php echo base_url()?>../assets/css/bootstrap.min.css" rel="stylesheet" />
  </head>
  <body>
    <div class="container">
      <div class="row text-center mt-5">
        <div class="col">
          <div class="p-2">
            <img
              style="width: 200px; border-radius: 10px;"
              src="../../../assets/img/logo.jpg"
            />
          </div>
          <h2>Sign in to your account</h2>
        </div>
      </div>
      <div class="row mt-5 justify-content-center">
        <div class="col-md-8 col-lg-6">
          <div class="card">
            <div class="card-body">
              <form action="login" method="post">
                <div class="mb-3">
                  <label for="inputEmail" class="form-label"
                    >Email address</label
                  >
                  <input
                    type="email"
                    name="email"
                    class="form-control"
                    id="inputEmail"
                    aria-describedby="emailHelp"
                    value="<?php echo set_value('email') ?>"
                  />
                  <a style="color:#FF0000;"><?php echo form_error('email') ?></a>
                </div>
                <div class="mb-3">
                  <label for="inputPassword" class="form-label">Password</label>
                  <input
                    type="password"
                    name="password"
                    class="form-control"
                    id="inputPassword"
                    value="<?php echo set_value('password') ?>"
                  />
                  <a style="color:#FF0000;"><?php echo form_error('password') ?></a>
                </div>
                <div class="d-flex w-100 justify-content-between mb-3">
                  <div class="form-check">
                    <input
                      type="checkbox"
                      class="form-check-input"
                      id="checkRememberMe"
                    />
                    <label class="form-check-label" for="checkRememberMe"
                      >Remember me</label
                    >
                  </div>
                  <div>
                    <a href="<?php echo base_url()?>/" class="link-primary">Forgot your password?</a>
                  </div>
                </div>

                <button type="submit" class="btn btn-primary w-100">
                  Sign in
                </button>
              </form>
              <hr />
              <div class="text-center">
                <a href="<?php echo base_url()?>/" class="link-secondary">Go back to homepage</a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script src="<?php echo base_url()?>../assets/js/bootstrap.bundle.min.js"></script>
  </body>
</html>