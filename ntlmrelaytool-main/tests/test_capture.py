def test_start_capture():
    from src.modules.capture.responder import ResponderCapture

    responder = ResponderCapture()
    assert responder is not None 

def test_stop_capture():
    from src.modules.capture.responder import ResponderCapture

    responder = ResponderCapture()
    assert responder is not None
    responder.stop_listener() 
    assert responder.running is False

def test_parse_hashes():
    from src.modules.capture.parser import parse_hashes

    raw_data = "user:hash"
    expected_output = {"username": "user", "hash": "hash"}
    assert parse_hashes(raw_data) == [expected_output]

def test_parse_hashes_empty():
    from src.modules.capture.parser import parse_hashes

    raw_data = ""
    expected_output = [] 
    assert parse_hashes(raw_data) == expected_output