from client.collect import run_dir


def test_is_alive(fs, fake_process):
    script_directory = '/tmp/collect'
    script_path = f'{script_directory}/script.sh'
    fs.create_dir(script_directory)
    fs.create_file(script_path, st_mode=0o555)
    fake_process.register_subprocess((script_path,))
    run_dir(script_directory, False, False)
